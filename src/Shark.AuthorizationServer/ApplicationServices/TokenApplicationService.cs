using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class TokenApplicationService : ITokenApplicationService
{
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const string RefreshTokenGrantType = "refresh_token";

    private const string DefaultAccessTokenType = "Bearer";

    private readonly IClientRepository _clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService;
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore;
    private readonly AuthorizationServerConfiguration _configuration;
    private readonly ILogger<TokenApplicationService> _logger;

    public TokenApplicationService(
        IClientRepository clientRepository,
        IStringGeneratorService stringGeneratorService,
        IAccessTokenGeneratorService accessTokenGeneratorService,
        IPersistedGrantStore persistedGrantStore,
        IOptions<AuthorizationServerConfiguration> options,
        ILogger<TokenApplicationService> logger)
    {
        _clientRepository = clientRepository;
        _stringGeneratorService = stringGeneratorService;
        _accessTokenGeneratorService = accessTokenGeneratorService;
        _persistedGrantStore = persistedGrantStore;
        _configuration = options.Value;
        _logger = logger;
    }

    public TokenInternalBaseResponse Execute(TokenInternalRequest request)
    {
        // Validate client
        var client = _clientRepository.GetById(request.ClientId);
        if (client is null ||
            !string.Equals(client.ClientSecret, request.ClientSecret, StringComparison.Ordinal) ||
            !client.RedirectUris.Contains(request.RedirectUrl))
        {
            return new TokenInternalBadRequestResponse("Invalid client");
        }

        // Validate grant type
        if (string.Equals(request.GrantType, AuthorizationCodeGrantType, StringComparison.Ordinal))
        {
            // Validate grant
            var codePersistedGrant = _persistedGrantStore.Get(request.Code);
            if (codePersistedGrant is null)
            {
                return new TokenInternalBadRequestResponse("Invalid grant");
            }

            if (!string.Equals(codePersistedGrant.ClientId, request.ClientId, StringComparison.Ordinal))
            {
                return new TokenInternalBadRequestResponse("Invalid grant");
            }

            _logger.LogInformation(
                "Found matching authorization code {code}. Issuing access token and refresh token",
                request.Code);

            // Generate bearer token
            var token = GenerateAndStoreBearerToken(request.ClientId, request.Scopes);
            return new TokenInternalResponse(JsonConvert.SerializeObject(token));
        }
        else if (string.Equals(request.GrantType, RefreshTokenGrantType, StringComparison.Ordinal))
        {
            // Validate grant
            var refreshTokenPersistedGrant = _persistedGrantStore.Get(request.RefreshToken);
            if (refreshTokenPersistedGrant is null)
            {
                return new TokenInternalBadRequestResponse("Invalid grant");
            }

            if (!string.Equals(refreshTokenPersistedGrant.ClientId, request.ClientId, StringComparison.Ordinal))
            {
                return new TokenInternalBadRequestResponse("Invalid grant");
            }

            _logger.LogInformation(
                "Found matching refresh token {refreshToken}. Issuing access token and refresh token",
                request.RefreshToken);

            // Generate bearer token
            var token = GenerateAndStoreBearerToken(request.ClientId, request.Scopes);
            return new TokenInternalResponse(JsonConvert.SerializeObject(token));
        }

        return new TokenInternalBadRequestResponse("Invalid grant_type");
    }

    private TokenResponse GenerateAndStoreBearerToken(string clientId, string[] scopes)
    {
        var userId = Guid.NewGuid().ToString();
        var accessToken = _accessTokenGeneratorService.Generate(userId, scopes);
        var refreshToken = _stringGeneratorService.GenerateRefreshToken();

        var token = new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = DefaultAccessTokenType,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        var tokenPersistedGrant = new PersistedGrant
        {
            Type = RefreshTokenGrantType,
            ClientId = clientId,
            Value = refreshToken,
            ExpiredIn = _configuration.AccessTokenExpirationInSeconds * 24,
        };

        _persistedGrantStore.Add(tokenPersistedGrant);

        return token;
    }
}