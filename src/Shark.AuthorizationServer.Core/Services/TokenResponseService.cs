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

    public (TokenResponse TokenResponse, string AccessTokenId) Generate(
        string clientId,
        string audience,
        string[] scopes,
        IEnumerable<CustomClaim>? claims = null)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        var accessToken = _accessTokenGeneratorService.Generate(scopes, audience, claims);
        var refreshToken = _refreshTokenGeneratorService.Generate(scopes);
        var idToken = _idTokenGeneratorService.Generate(clientId, scopes, claims);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken.Value,
            RefreshToken = refreshToken,
            IdToken = idToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return (tokenResponse, accessToken.Id);
    }

    public TokenResponse GenerateForAccessTokenOnly(string audience, string[] scopes, IEnumerable<CustomClaim>? claims = null)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        var accessToken = _accessTokenGeneratorService.Generate(scopes, audience, claims);

        var tokenResponse = new TokenResponse
        {
            AccessToken = accessToken.Value,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return tokenResponse;
    }
}