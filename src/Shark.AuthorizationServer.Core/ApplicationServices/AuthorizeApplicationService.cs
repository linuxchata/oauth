﻿using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class AuthorizeApplicationService(
    IAuthorizeValidator authorizeValidator,
    IStringGeneratorService stringGeneratorService,
    ITokenResponseService tokenResponseService,
    IRedirectionService redirectionService,
    IClientRepository clientRepository,
    IPersistedGrantRepository persistedGrantRepository,
    ILogger<AuthorizeApplicationService> logger) : IAuthorizeApplicationService
{
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IAuthorizeValidator _authorizeValidator = authorizeValidator;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly ITokenResponseService _tokenResponseService = tokenResponseService;
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly ILogger<AuthorizeApplicationService> _logger = logger;

    public async Task<IAuthorizeInternalResponse> Execute(
        AuthorizeInternalRequest request,
        ClaimsPrincipal userIdentity)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        using var loggerScope = _logger.BeginScope("ClientId:{ClientId}", request.ClientId.Sanitize());

        var client = await _clientRepository.Get(request.ClientId);

        var response = _authorizeValidator.ValidateRequest(request, client);
        if (response != null)
        {
            return response;
        }

        var customClaims = userIdentity?.Claims?.Select(c => new CustomClaim(c.Type, c.Value)).ToArray() ?? [];

        if (IsResponseType(request.ResponseType, ResponseType.Code))
        {
            return await HandleCodeResponse(request, customClaims);
        }
        else if (IsResponseType(request.ResponseType, ResponseType.Token))
        {
            return HandleTokenResponse(request, client!, customClaims);
        }

        throw new InvalidOperationException($"Unsupported response type {request.ResponseType}");
    }

    private static bool IsResponseType(string responseType, string expectedResponseType)
    {
        return responseType.EqualsTo(expectedResponseType);
    }

    private async Task<AuthorizeInternalCodeResponse> HandleCodeResponse(
        AuthorizeInternalRequest request,
        IEnumerable<CustomClaim> claims)
    {
        _logger.LogInformation("Issuing authorization code. Response type is {ResponseType}", ResponseType.Code);

        var code = _stringGeneratorService.GenerateCode();

        await StorePersistedGrant(request, code, claims);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            code,
            request.Scopes,
            request.State);

        return new AuthorizeInternalCodeResponse(redirectUrl);
    }

    private AuthorizeInternalTokenResponse HandleTokenResponse(
        AuthorizeInternalRequest request,
        Client client,
        IEnumerable<CustomClaim> claims)
    {
        _logger.LogInformation("Issuing access token. Response type is {ResponseType}", ResponseType.Token);

        var tokenResponse = _tokenResponseService.GenerateForAccessTokenOnly(client.Audience, request.Scopes, claims);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            tokenResponse.AccessToken,
            tokenResponse.TokenType);

        return new AuthorizeInternalTokenResponse(redirectUrl);
    }

    private async Task StorePersistedGrant(
        AuthorizeInternalRequest request,
        string code,
        IEnumerable<CustomClaim> claims)
    {
        // code_challenge_method defaults to "plain" if not present in the request
        var codeChallengeMethod = request.CodeChallengeMethod;
        if (!string.IsNullOrWhiteSpace(request.CodeChallenge) &&
            string.IsNullOrWhiteSpace(request.CodeChallengeMethod))
        {
            codeChallengeMethod = CodeChallengeMethod.Plain;
        }

        var persistedGrant = new PersistedGrant
        {
            Type = GrantType.AuthorizationCode,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            Value = code,
            Claims = claims.ToArray(),
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            CreatedDate = DateTime.UtcNow,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };

        await _persistedGrantRepository.Add(persistedGrant);
    }
}