using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.Core.Services;

public sealed class TokenResponseService(
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IIdTokenGeneratorService idTokenGeneratorService,
    IRefreshTokenGeneratorService refreshTokenGeneratorService,
    IOptions<AuthorizationServerConfiguration> options) : ITokenResponseService
{
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IIdTokenGeneratorService _idTokenGeneratorService = idTokenGeneratorService;
    private readonly IRefreshTokenGeneratorService _refreshTokenGeneratorService = refreshTokenGeneratorService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public (TokenResponse TokenResponse, AccessToken AccessToken) Generate(
        string clientId,
        string audience,
        string[] scopes,
        string userId,
        string? userName = null)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));

        var accessToken = _accessTokenGeneratorService.Generate(userId, userName, scopes, audience);
        var refreshToken = _refreshTokenGeneratorService.Generate(scopes);
        var idToken = _idTokenGeneratorService.Generate(userId, userName, clientId, scopes);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken.Value,
            RefreshToken = refreshToken,
            IdToken = idToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return (tokenResponse, accessToken);
    }

    public TokenResponse GenerateForAccessTokenOnly(string audience, string[] scopes, string? userId = null)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        var accessToken = _accessTokenGeneratorService.Generate(userId, null, scopes, audience);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return tokenResponse;
    }
}