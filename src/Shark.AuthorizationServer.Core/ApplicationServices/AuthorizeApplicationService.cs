using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class AuthorizeApplicationService(
    IAuthorizeValidator authorizeValidator,
    IStringGeneratorService stringGeneratorService,
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IRedirectionService redirectionService,
    IClientRepository clientRepository,
    IPersistedGrantRepository persistedGrantRepository,
    IHttpContextAccessor httpContextAccessor,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<AuthorizeApplicationService> logger) : IAuthorizeApplicationService
{
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IAuthorizeValidator _authorizeValidator = authorizeValidator;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<AuthorizeApplicationService> _logger = logger;

    public async Task<IAuthorizeInternalResponse> Execute(AuthorizeInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var client = await _clientRepository.Get(request.ClientId);

        var response = _authorizeValidator.ValidateRequest(request, client);
        if (response != null)
        {
            return response;
        }

        if (IsResponseType(request.ResponseType, ResponseType.Code))
        {
            return await HandleCodeResponse(request, client!);
        }
        else if (IsResponseType(request.ResponseType, ResponseType.Token))
        {
            return HandleTokenResponse(request, client!);
        }

        return HandleUnsupportedResponseType(request.ResponseType, client!);
    }

    private static bool IsResponseType(string responseType, string expectedResponseType)
    {
        return responseType.EqualsTo(expectedResponseType);
    }

    private async Task<AuthorizeInternalCodeResponse> HandleCodeResponse(
        AuthorizeInternalRequest request,
        Client client)
    {
        _logger.LogInformation(
            "Issuing authorization code for client [{ClientId}]. Response type is {ResponseType}",
            client.ClientId,
            ResponseType.Code);

        var code = _stringGeneratorService.GenerateCode();

        await StorePersistedGrant(request, code);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            code,
            request.Scopes,
            request.State);

        return new AuthorizeInternalCodeResponse(redirectUrl);
    }

    private AuthorizeInternalTokenResponse HandleTokenResponse(AuthorizeInternalRequest request, Client client)
    {
        _logger.LogInformation(
            "Issuing access token for client [{ClientId}]. Response type is {ResponseType}",
            client.ClientId,
            ResponseType.Token);

        var token = GenerateBearerToken(client!, request.Scopes);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            token.AccessToken,
            token.TokenType);

        return new AuthorizeInternalTokenResponse(redirectUrl);
    }

    private AuthorizeInternalBadRequestResponse HandleUnsupportedResponseType(string responseType, Client client)
    {
        _logger.LogWarning(
            "Unsupported response type {ResponseType}. Client is [{ClientId}]",
            responseType,
            client.ClientId);

        return new AuthorizeInternalBadRequestResponse(Error.InvalidResponseType);
    }

    private async Task StorePersistedGrant(AuthorizeInternalRequest request, string code)
    {
        var userName = _httpContextAccessor.HttpContext?.User.Identity?.Name;

        var persistedGrant = new PersistedGrant
        {
            Type = GrantType.AuthorizationCode,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            Value = code,
            UserName = userName,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            CreatedDate = DateTime.UtcNow,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };

        await _persistedGrantRepository.Add(persistedGrant);
    }

    private TokenResponse GenerateBearerToken(Client client, string[] scopes)
    {
        var userId = Guid.NewGuid().ToString();
        var accessToken = _accessTokenGeneratorService.Generate(userId, null, scopes, client.Audience);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return tokenResponse;
    }
}