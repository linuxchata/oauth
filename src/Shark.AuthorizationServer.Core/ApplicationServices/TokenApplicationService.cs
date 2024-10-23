using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class TokenApplicationService(
    IClientRepository clientRepository,
    IPersistedGrantRepository persistedGrantRepository,
    IStringGeneratorService stringGeneratorService,
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IIdTokenGeneratorService idTokenGeneratorService,
    IResourceOwnerCredentialsValidationService resourceOwnerCredentialsValidationService,
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<TokenApplicationService> logger) : ITokenApplicationService
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IIdTokenGeneratorService _idTokenGeneratorService = idTokenGeneratorService;
    private readonly IResourceOwnerCredentialsValidationService _resourceOwnerCredentialsValidationService = resourceOwnerCredentialsValidationService;
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public async Task<TokenInternalBaseResponse> Execute(TokenInternalRequest request, ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            request.ClientId = claimsPrincipal.FindFirstValue(Scope.ClientId);
        }

        var client = await _clientRepository.Get(request.ClientId);

        var response = ValidateRequest(request, client, claimsPrincipal);
        if (response != null)
        {
            return response;
        }

        if (IsGrantType(request.GrantType, GrantType.AuthorizationCode))
        {
            return await HandleAuthorizationCodeGrantType(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.RefreshToken))
        {
            return await HandleRefreshTokenGrantType(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.ClientCredentials))
        {
            return HandleClientCredentialsGrantType(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.ResourceOwnerCredentials))
        {
            return await HandleResourceOwnerCredentialsGrantType(request, client!);
        }
        else if (IsGrantType(request.GrantType, GrantType.DeviceCode))
        {
            return await HandleDeviceCodeGrantType(request, client!);
        }

        return HandleUnsupportedGrantType(request);
    }

    private TokenInternalBadRequestResponse? ValidateRequest(
        TokenInternalRequest request,
        Client? client,
        ClaimsPrincipal claimsPrincipal)
    {
        // Validate client
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{clientId}]", request.ClientId);
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate client secret
        if (!claimsPrincipal.Identity?.IsAuthenticated ?? true)
        {
            if (!client.ClientSecret.EqualsTo(request.ClientSecret))
            {
                _logger.LogWarning("Invalid client secret for client [{clientId}]", request.ClientId);
                return new TokenInternalBadRequestResponse(Error.InvalidClient);
            }
        }

        // Validate redirect URI
        if (!string.IsNullOrWhiteSpace(request.RedirectUri) &&
            !client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning(
                "Mismatched redirect URL [{redirectUri}] for client [{clientId}]",
                request.RedirectUri,
                request.ClientId);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate requested scopes against client's allowed scopes
        var allowedClientScopes = client.Scope.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning(
                    "Mismatched scope [{scope}] for client [{clientId}]",
                    scope,
                request.ClientId);
                return new TokenInternalBadRequestResponse(Error.InvalidScope);
            }
        }

        return null;
    }

    private bool IsGrantType(string? grantType, string expectedGrantType)
    {
        return grantType.EqualsTo(expectedGrantType);
    }

    private async Task<TokenInternalBaseResponse> HandleAuthorizationCodeGrantType(
        TokenInternalRequest request,
        Client client)
    {
        var persistedGrant = await _persistedGrantRepository.Get(request.Code);

        var response = ValidateCodeGrant(persistedGrant, request);
        if (response != null)
        {
            return response;
        }

        // Remove code persisted grant, since it can be considered consumed at this point
        await _persistedGrantRepository.Remove(request.Code);

        _logger.LogInformation(
            "Found matching authorization code {code}. Issuing access token and refresh token for {grantType}",
            request.Code,
            GrantType.AuthorizationCode);

        var token = await GenerateAndStoreBearerToken(client, request.RedirectUri, request.Scopes, persistedGrant!.UserName);
        return new TokenInternalResponse(token);
    }

    private async Task<TokenInternalBaseResponse> HandleRefreshTokenGrantType(
        TokenInternalRequest request,
        Client client)
    {
        var persistedGrant = await _persistedGrantRepository.Get(request.RefreshToken);

        var response = ValidateRefreshTokenGrant(persistedGrant, request);
        if (response != null)
        {
            // Remove refresh token persisted grant if it exists, since it can be compromised
            await _persistedGrantRepository.Remove(request.RefreshToken);

            return response;
        }

        // Remove previous refresh token
        await _persistedGrantRepository.Remove(request.RefreshToken);

        _logger.LogInformation(
            "Found matching refresh token {refreshToken}. Issuing access token and refresh token for {grantType}",
            request.RefreshToken,
            GrantType.RefreshToken);

        var token = await GenerateAndStoreBearerToken(client!, request.RedirectUri, persistedGrant!.Scopes, persistedGrant!.UserName);
        return new TokenInternalResponse(token);
    }

    private TokenInternalResponse HandleClientCredentialsGrantType(TokenInternalRequest request, Client client)
    {
        _logger.LogInformation("Issuing access token for {grantType}", GrantType.ClientCredentials);

        var token = GenerateBearerToken(client!, request.Scopes);
        return new TokenInternalResponse(token);
    }

    private async Task<TokenInternalBaseResponse> HandleResourceOwnerCredentialsGrantType(
        TokenInternalRequest request,
        Client client)
    {
        if (!_resourceOwnerCredentialsValidationService.ValidateCredentials(request.Username, request.Password))
        {
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        _logger.LogInformation("Issuing access token for {grantType}", GrantType.ResourceOwnerCredentials);

        var token = await GenerateAndStoreBearerToken(client!, request.RedirectUri, request.Scopes, request.Username);
        return new TokenInternalResponse(token);
    }

    private async Task<TokenInternalBaseResponse> HandleDeviceCodeGrantType(TokenInternalRequest request, Client client)
    {
        if (string.IsNullOrWhiteSpace(request.DeviceCode))
        {
            return new TokenInternalBadRequestResponse(Error.InvalidRequest);
        }

        var devicePersistedGrant = await _persistedGrantRepository.GetByDeviceCode(request.DeviceCode);

        var response = ValidateDeviceCodeGrant(devicePersistedGrant, request);
        if (response != null)
        {
            return response;
        }

        if (!devicePersistedGrant!.IsAuthorized)
        {
            _logger.LogWarning(
                "User did not authorize client [{clientId}] for {grantType} grant",
                request.ClientId,
                GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.AuthorizationPending);
        }

        // Remove device code persisted grant, since it can be considered consumed at this point
        await _persistedGrantRepository.Remove(request.DeviceCode);

        _logger.LogInformation("Issuing access token for {grantType} grant", GrantType.DeviceCode);

        var token = await GenerateAndStoreBearerToken(client!, null, request.Scopes);
        return new TokenInternalResponse(token);
    }

    private TokenInternalBadRequestResponse HandleUnsupportedGrantType(TokenInternalRequest request)
    {
        _logger.LogWarning("Unsupported grant type {grantType}", request.GrantType);
        return new TokenInternalBadRequestResponse(Error.InvalidGrantType);
    }

    private TokenInternalBadRequestResponse? ValidateCodeGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for code persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI for code persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = persistedGrant.Scopes.ToHashSet() ?? [];
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope for code persisted grant");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate grant's code verifier
        if (!string.IsNullOrWhiteSpace(persistedGrant.CodeChallenge))
        {
            if (string.IsNullOrWhiteSpace(request.CodeVerifier))
            {
                _logger.LogWarning("Code verifier was not found in request");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }

            string codeChallenge;

            if (persistedGrant.CodeChallengeMethod.EqualsTo(CodeChallengeMethod.Plain))
            {
                codeChallenge = request.CodeVerifier;
            }
            else if (persistedGrant.CodeChallengeMethod.EqualsTo(CodeChallengeMethod.Sha256))
            {
                codeChallenge = _proofKeyForCodeExchangeService.GetCodeChallenge(
                    request.CodeVerifier,
                    persistedGrant.CodeChallengeMethod!);
            }
            else
            {
                return new TokenInternalBadRequestResponse(Error.InvalidRequest);
            }

            if (!persistedGrant.CodeChallenge.EqualsTo(codeChallenge))
            {
                _logger.LogWarning("Mismatched code challenge for code persisted grant");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        return null;
    }

    private TokenInternalBadRequestResponse? ValidateRefreshTokenGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for refresh token persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI for refresh token persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    private TokenInternalBadRequestResponse? ValidateDeviceCodeGrant(
        DevicePersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for {grantType} persisted grant", GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = persistedGrant.Scopes.ToHashSet() ?? [];
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope for {grantType} persisted grant", GrantType.DeviceCode);
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate grant's device code
        if (!persistedGrant.DeviceCode.EqualsTo(request.DeviceCode))
        {
            _logger.LogWarning("Mismatched device code for {grantType} persisted grant", GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    private async Task<TokenResponse> GenerateAndStoreBearerToken(
        Client client,
        string? redirectUri,
        string[] scopes,
        string? userName = null)
    {
        var userId = Guid.NewGuid().ToString();
        var accessToken = _accessTokenGeneratorService.Generate(userId, userName, scopes, client.Audience);
        var idToken = _idTokenGeneratorService.Generate(userId, userName, client.ClientId, scopes);
        var refreshToken = _stringGeneratorService.GenerateRefreshToken();

        var token = new TokenResponse
        {
            AccessToken = accessToken.Value,
            RefreshToken = refreshToken,
            IdToken = idToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        var tokenPersistedGrant = new PersistedGrant
        {
            Type = GrantType.RefreshToken,
            ClientId = client.ClientId,
            RedirectUri = redirectUri,
            Scopes = scopes,
            AccessTokenId = accessToken.Id, // Jti (token identifier) is needed to revoke refresh token when access token is revoked
            Value = refreshToken,
            UserName = userName,
            ExpiredIn = _configuration.AccessTokenExpirationInSeconds * 24,
        };

        await _persistedGrantRepository.Add(tokenPersistedGrant);

        return token;
    }

    private TokenResponse GenerateBearerToken(Client client, string[] scopes)
    {
        var accessToken = _accessTokenGeneratorService.Generate(null, null, scopes, client.Audience);

        var token = new TokenResponse
        {
            AccessToken = accessToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return token;
    }
}