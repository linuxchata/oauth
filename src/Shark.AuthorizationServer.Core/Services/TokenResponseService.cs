using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.Services;

public sealed class TokenResponseService(
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IIdTokenGeneratorService idTokenGeneratorService,
    IStringGeneratorService stringGeneratorService,
    IOptions<AuthorizationServerConfiguration> options) : ITokenResponseService
{
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IIdTokenGeneratorService _idTokenGeneratorService = idTokenGeneratorService;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
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
        var idToken = _idTokenGeneratorService.Generate(userId, userName, clientId, scopes);
        var refreshToken = _stringGeneratorService.GenerateRefreshToken();

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