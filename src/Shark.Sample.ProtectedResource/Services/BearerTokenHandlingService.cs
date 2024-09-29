using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Shark.Sample.ProtectedResource.Constants;
using Shark.Sample.ProtectedResource.Models;

namespace Shark.Sample.ProtectedResource.Services;

public sealed class BearerTokenHandlingService(
    IOptions<BearerTokenAuthenticationOptions> options) : IBearerTokenHandlingService
{
    private const string HeaderKeyName = "Authorization";
    private const string BearerTokenName = "Bearer";

    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;

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

        if (!authorization.StartsWith(BearerTokenName, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var startIndexOfAccessToken = authorization.IndexOf(BearerTokenName) + 1;
        var accessToken = authorization.Substring(startIndexOfAccessToken + BearerTokenName.Length);

        return accessToken;
    }

    public bool ParseAccessToken(string accessToken, out TokenIdentity tokenIdentity)
    {
        tokenIdentity = new TokenIdentity();

        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(accessToken))
        {
            var jwtToken = handler.ReadJwtToken(accessToken);
            return ValidateAccessToken(jwtToken, out tokenIdentity);
        }

        return true;
    }

    private bool ValidateAccessToken(JwtSecurityToken jwtToken, out TokenIdentity tokenIdentity)
    {
        tokenIdentity = new TokenIdentity();

        // Validate subject
        var userId = jwtToken.Subject;

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
        var scopes = claims.FirstOrDefault(c => c.Type == ClaimType.Scope)?.Value?.Split(' ');

        tokenIdentity.UserId = userId;
        tokenIdentity.Scopes = scopes!;

        return true;
    }
}