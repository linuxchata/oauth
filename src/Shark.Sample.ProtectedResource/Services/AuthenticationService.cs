using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Shark.Sample.ProtectedResource.Models;

namespace Shark.Sample.ProtectedResource.Services;

public sealed class AuthenticationService : IAuthenticationService
{
    private const string HeaderKeyName = "Authorization";
    private const string BearerTokenName = "Bearer";

    private readonly AuthorizationClientConfiguration _configuration;

    public AuthenticationService(IOptions<AuthorizationClientConfiguration> options)
    {
        _configuration = options.Value;
    }

    public bool IsAuthenticated(IHeaderDictionary headers)
    {
        if (!headers.TryGetValue(HeaderKeyName, out StringValues headerValue))
        {
            return false;
        };

        if (headerValue == StringValues.Empty)
        {
            return false;
        }

        var authorization = headerValue.ToString();

        if (!authorization.StartsWith(BearerTokenName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var startIndexOfAccessToken = authorization.IndexOf(BearerTokenName) + 1;
        var accessToken = authorization.Substring(startIndexOfAccessToken + BearerTokenName.Length);

        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(accessToken))
        {
            var jwtToken = handler.ReadJwtToken(accessToken);
            return ValidateAccessToken(jwtToken);
        }

        return true;
    }

    private bool ValidateAccessToken(JwtSecurityToken jwtToken)
    {
        // Validate subject
        var userId = jwtToken.Subject;
        if (string.IsNullOrWhiteSpace(userId))
        {
            return false;
        }

        // Validate issuer
        var issuer = jwtToken.Issuer;
        if (!string.Equals(issuer, _configuration.Issuer, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Validate audience
        var audiences = jwtToken.Audiences.ToHashSet();
        if (!audiences.Contains(_configuration.Audience))
        {
            return false;
        }

        // Validate time
        var currentTime = DateTime.UtcNow;
        if (currentTime < jwtToken.ValidFrom)
        {
            return false;
        }
        else if (currentTime > jwtToken.ValidTo)
        {
            return false;
        }

        var claims = jwtToken.Claims;
        var scopes = claims.FirstOrDefault(c => c.Type == "scope")?.Value?.Split(' ');

        return true;
    }
}