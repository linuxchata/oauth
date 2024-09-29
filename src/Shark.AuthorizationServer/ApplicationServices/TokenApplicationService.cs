using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class TokenApplicationService(
    IClientRepository clientRepository,
    IStringGeneratorService stringGeneratorService,
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IPersistedGrantStore persistedGrantStore,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<TokenApplicationService> logger) : ITokenApplicationService
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public TokenInternalBaseResponse Execute(TokenInternalRequest request)
    {
        var client = _clientRepository.GetById(request.ClientId);

        var response = ValidateClient(client, request);
        if (response != null)
        {
            return response;
        }

        if (string.Equals(request.GrantType, GrantType.AuthorizationCode, StringComparison.Ordinal))
        {
            var persistedGrant = _persistedGrantStore.Get(request.Code);

            response = ValidateCodeGrant(persistedGrant, request);
            if (response != null)
            {
                return response;
            }

            // Remove code persisted grant, since it can be considered consumed at this point
            _persistedGrantStore.Remove(request.Code);

            _logger.LogInformation(
                "Found matching authorization code {code}. Issuing access token and refresh token for {grantType}",
                request.Code,
                GrantType.AuthorizationCode);

            var token = GenerateAndStoreBearerToken(client!, request.Scopes, persistedGrant!.UserName);
            return new TokenInternalResponse(JsonConvert.SerializeObject(token));
        }
        else if (string.Equals(request.GrantType, GrantType.RefreshToken, StringComparison.Ordinal))
        {
            var persistedGrant = _persistedGrantStore.Get(request.RefreshToken);

            response = ValidateRefreshTokenGrant(persistedGrant, request);
            if (response != null)
            {
                // Remove refresh token persisted grant if it exists, since it can be compromised
                _persistedGrantStore.Remove(request.RefreshToken);

                return response;
            }

            // Remove previous refresh token
            _persistedGrantStore.Remove(request.RefreshToken);

            _logger.LogInformation(
                "Found matching refresh token {refreshToken}. Issuing access token and refresh token for {grantType}",
                request.RefreshToken,
                GrantType.RefreshToken);

            var token = GenerateAndStoreBearerToken(client!, request.Scopes, persistedGrant!.UserName);
            return new TokenInternalResponse(JsonConvert.SerializeObject(token));
        }
        else if (string.Equals(request.GrantType, GrantType.ClientCredentials, StringComparison.Ordinal))
        {
            _logger.LogInformation(
                "Issuing access token for {grantType}",
                GrantType.ClientCredentials);

            var token = GenerateBearerToken(client!, request.Scopes);
            return new TokenInternalResponse(JsonConvert.SerializeObject(token));
        }

        _logger.LogWarning("Unsupported grant type {grantType}", request.GrantType);
        return new TokenInternalBadRequestResponse(Error.InvalidGrantType);
    }

    private TokenInternalBadRequestResponse? ValidateClient(Client? client, TokenInternalRequest request)
    {
        // Validate client
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{clientId}]", request.ClientId);
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        if (!string.Equals(client.ClientSecret, request.ClientSecret, StringComparison.Ordinal))
        {
            _logger.LogWarning("Invalid client secret");
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        if (!string.IsNullOrWhiteSpace(request.RedirectUrl) &&
            !client.RedirectUris.Contains(request.RedirectUrl))
        {
            _logger.LogWarning("Mismatched redirect URL [{redirectUrl}]", request.RedirectUrl);
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate requested scopes against client's allowed scopes
        var allowedClientScopes = client.AllowedScopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                return new TokenInternalBadRequestResponse(Error.InvalidClient);
            }
        }

        return null;
    }

    private TokenInternalBadRequestResponse? ValidateCodeGrant
        (PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant client
        if (!string.Equals(persistedGrant.ClientId, request.ClientId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Mismatched client identifier for code persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant scopes
        var allowedScopes = persistedGrant.Scopes?.ToHashSet() ?? [];
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope for code persisted grant");
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

        // Validate grant client
        if (!string.Equals(persistedGrant.ClientId, request.ClientId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Mismatched client identifier for refresh token persisted grant");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    private TokenResponse GenerateAndStoreBearerToken(
        Client client,
        string[] scopes,
        string? userName = null)
    {
        var userId = Guid.NewGuid().ToString();
        var accessToken = _accessTokenGeneratorService.Generate(userId, userName, scopes, client.Audience);
        var refreshToken = _stringGeneratorService.GenerateRefreshToken();

        var token = new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        var tokenPersistedGrant = new PersistedGrant
        {
            Type = GrantType.RefreshToken,
            ClientId = client.ClientId,
            Value = refreshToken,
            ExpiredIn = _configuration.AccessTokenExpirationInSeconds * 24,
        };

        _persistedGrantStore.Add(tokenPersistedGrant);

        return token;
    }

    private TokenResponse GenerateBearerToken(Client client, string[] scopes)
    {
        var accessToken = _accessTokenGeneratorService.Generate(null, null, scopes, client.Audience);

        var token = new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return token;
    }
}