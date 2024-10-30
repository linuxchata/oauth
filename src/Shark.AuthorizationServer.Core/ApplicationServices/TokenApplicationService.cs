using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class TokenApplicationService(
    ITokenValidator tokenValidator,
    IClientRepository clientRepository,
    IPersistedGrantRepository persistedGrantRepository,
    IDevicePersistedGrantRepository devicePersistedGrantRepository,
    ITokenResponseService tokenResponseService,
    IResourceOwnerCredentialsValidationService resourceOwnerCredentialsValidationService,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<TokenApplicationService> logger) : ITokenApplicationService
{
    private readonly ITokenValidator _tokenValidator = tokenValidator;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly IDevicePersistedGrantRepository _devicePersistedGrantRepository = devicePersistedGrantRepository;
    private readonly ITokenResponseService _tokenResponseService = tokenResponseService;
    private readonly IResourceOwnerCredentialsValidationService _resourceOwnerCredentialsValidationService = resourceOwnerCredentialsValidationService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public async Task<ITokenInternalResponse> Execute(TokenInternalRequest request, ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            request.ClientId = claimsPrincipal.FindFirstValue(Scope.ClientId);
        }

        using var scope = _logger.BeginScope("ClientId: {ClientId} =>", request.ClientId!);

        var client = await _clientRepository.Get(request.ClientId);

        var response = _tokenValidator.ValidateRequest(request, client, claimsPrincipal);
        if (response != null)
        {
            return response;
        }

        if (IsGrantType(request.GrantType, GrantType.AuthorizationCode))
        {
            return await HandleAuthorizationCode(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.RefreshToken))
        {
            return await HandleRefreshTokenGrant(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.ClientCredentials))
        {
            return HandleClientCredentialsGrant(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.ResourceOwnerCredentials))
        {
            return await HandleResourceOwnerCredentialsGrant(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.DeviceCode))
        {
            return await HandleDeviceCodeGrant(request, client!);
        }

        return HandleUnsupportedGrantType(request);
    }

    private static bool IsGrantType(string? grantType, string expectedGrantType)
    {
        return grantType.EqualsTo(expectedGrantType);
    }

    private async Task<ITokenInternalResponse> HandleAuthorizationCode(TokenInternalRequest request, Client client)
    {
        var persistedGrant = await _persistedGrantRepository.Get(request.Code);

        var response = _tokenValidator.ValidateCodeGrant(persistedGrant, request);
        if (response != null)
        {
            return response;
        }

        // Remove code persisted grant, since it can be considered consumed at this point
        await _persistedGrantRepository.Remove(request.Code);

        _logger.LogInformation(
            "Found matching authorization code {Code}. Issuing access token and refresh token for {GrantType} grant",
            request.Code,
            GrantType.AuthorizationCode);

        var tokenResponse = await GenerateAndStoreBearerToken(
            client.ClientId, client.Audience, request.RedirectUri, request.Scopes, persistedGrant!.UserName);

        return new TokenInternalResponse(tokenResponse);
    }

    private async Task<ITokenInternalResponse> HandleRefreshTokenGrant(TokenInternalRequest request, Client client)
    {
        var persistedGrant = await _persistedGrantRepository.Get(request.RefreshToken);

        var response = _tokenValidator.ValidateRefreshTokenGrant(persistedGrant, request);
        if (response != null)
        {
            // Remove refresh token persisted grant if it exists, since it can be compromised
            await _persistedGrantRepository.Remove(request.RefreshToken);

            return response;
        }

        // Remove previous refresh token
        await _persistedGrantRepository.Remove(request.RefreshToken);

        _logger.LogInformation(
            "Found matching refresh token {RefreshToken}. Issuing access token and refresh token for {GrantType}",
            request.RefreshToken,
            GrantType.RefreshToken);

        var tokenResponse = await GenerateAndStoreBearerToken(
            client.ClientId, client.Audience, request.RedirectUri, persistedGrant!.Scopes, persistedGrant!.UserName);

        return new TokenInternalResponse(tokenResponse);
    }

    private TokenInternalResponse HandleClientCredentialsGrant(TokenInternalRequest request, Client client)
    {
        _logger.LogInformation("Issuing access token for {GrantType} grant", GrantType.ClientCredentials);

        var tokenResponse = _tokenResponseService.GenerateForAccessTokenOnly(client.Audience, request.Scopes);

        return new TokenInternalResponse(tokenResponse);
    }

    private async Task<ITokenInternalResponse> HandleResourceOwnerCredentialsGrant(TokenInternalRequest request, Client client)
    {
        if (!_resourceOwnerCredentialsValidationService.ValidateCredentials(request.Username, request.Password))
        {
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        _logger.LogInformation("Issuing access token for {GrantType} grant", GrantType.ResourceOwnerCredentials);

        var tokenResponse = await GenerateAndStoreBearerToken(
            client.ClientId, client.Audience, request.RedirectUri, request.Scopes, request.Username);

        return new TokenInternalResponse(tokenResponse);
    }

    private async Task<ITokenInternalResponse> HandleDeviceCodeGrant(TokenInternalRequest request, Client client)
    {
        if (string.IsNullOrWhiteSpace(request.DeviceCode))
        {
            return new TokenInternalBadRequestResponse(Error.InvalidRequest);
        }

        var devicePersistedGrant = await _devicePersistedGrantRepository.GetByDeviceCode(request.DeviceCode);

        var response = _tokenValidator.ValidateDeviceCodeGrant(devicePersistedGrant, request);
        if (response != null)
        {
            return response;
        }

        if (!devicePersistedGrant!.IsAuthorized)
        {
            _logger.LogWarning(
                "User did not authorize device code for {GrantType} grant",
                GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.AuthorizationPending);
        }

        // Remove device code persisted grant, since it can be considered consumed at this point
        await _devicePersistedGrantRepository.Remove(devicePersistedGrant);

        _logger.LogInformation("Issuing access token for {GrantType} grant", GrantType.DeviceCode);

        var tokenResponse = await GenerateAndStoreBearerToken(client.ClientId, client.Audience, null, request.Scopes);

        return new TokenInternalResponse(tokenResponse);
    }

    private TokenInternalBadRequestResponse HandleUnsupportedGrantType(TokenInternalRequest request)
    {
        _logger.LogWarning("Unsupported grant type {GrantType}", request.GrantType);
        return new TokenInternalBadRequestResponse(Error.InvalidGrantType);
    }

    private async Task<TokenResponse> GenerateAndStoreBearerToken(
        string clientId,
        string audience,
        string? redirectUri,
        string[] scopes,
        string? userName = null)
    {
        var userId = Guid.NewGuid().ToString();
        var result = _tokenResponseService.Generate(clientId, audience, scopes, userId, userName);

        if (!string.IsNullOrWhiteSpace(result.TokenResponse.RefreshToken))
        {
            var tokenPersistedGrant = new PersistedGrant
            {
                Type = GrantType.RefreshToken,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                AccessTokenId = result.AccessToken.Id, // Jti (token identifier) is needed to revoke refresh token when access token is revoked
                Value = result.TokenResponse.RefreshToken,
                UserName = userName,
                CreatedDate = DateTime.UtcNow,
                ExpiredIn = _configuration.AccessTokenExpirationInSeconds * 24,
            };

            await _persistedGrantRepository.Add(tokenPersistedGrant);
        }

        return result.TokenResponse;
    }
}