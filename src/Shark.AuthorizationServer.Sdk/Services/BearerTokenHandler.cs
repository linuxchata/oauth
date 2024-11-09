using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Configurations;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class BearerTokenHandler(
    ICustomAccessTokenHandler customAccessTokenHandler,
    IIntrospectionProvider introspectionProvider,
    IOptions<BearerTokenAuthenticationOptions> options,
    ILogger<BearerTokenHandler> logger) : IBearerTokenHandler
{
    private const string HeaderKeyName = "Authorization";

    private readonly ICustomAccessTokenHandler _customAccessTokenHandler = customAccessTokenHandler;
    private readonly IIntrospectionProvider _introspectionProvider = introspectionProvider;
    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;
    private readonly ILogger<BearerTokenHandler> _logger = logger;

    public string? GetAccessToken(IHeaderDictionary headers)
    {
        if (!headers.TryGetValue(HeaderKeyName, out StringValues headerValue))
        {
            return null;
        }

        if (headerValue == StringValues.Empty)
        {
            return null;
        }

        var authorization = headerValue.ToString();

        if (!authorization.StartsWith(Scheme.Bearer, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var startIndexOfAccessToken = authorization.IndexOf(Scheme.Bearer) + 1;
        var accessToken = authorization[(startIndexOfAccessToken + Scheme.Bearer.Length)..];

        return accessToken;
    }

    public async Task<TokenIdentity?> ParseAccessToken(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = _configuration.ValidateIssuer,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = _configuration.ValidateAudience,
            ValidAudiences = [_configuration.Audience],
        };

        var jwtToken = _customAccessTokenHandler.Read(accessToken, tokenValidationParameters);
        if (jwtToken == null)
        {
            return null;
        }

        if (_configuration.TokenIntrospection?.Enabled ?? false)
        {
            var isTokenValid = await _introspectionProvider.GetTokenStatus(accessToken);
            if (!isTokenValid)
            {
                return null;
            }
        }

        var userId = jwtToken.Subject;
        var scopes = jwtToken.Claims.FirstOrDefault(c => c.Type.EqualsTo(ClaimType.Scope))?.Value?.Split(' ');

        var tokenIdentity = new TokenIdentity
        {
            UserId = userId,
            Scopes = scopes!,
        };

        _logger.LogInformation(
            "Access token for user identifier {UserId} has been read and validated",
            userId);

        return tokenIdentity;
    }
}