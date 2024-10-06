using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
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
        var accessToken = authorization[(startIndexOfAccessToken + BearerTokenName.Length)..];

        return accessToken;
    }

    public bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity)
    {
        tokenIdentity = new TokenIdentity();

        var handler = new JwtSecurityTokenHandler();
        if (handler.CanReadToken(accessToken))
        {
            var jwtToken = handler.ReadJwtToken(accessToken);
            return ValidateAccessToken(jwtToken, accessToken, out tokenIdentity);
        }

        return true;
    }

    private bool ValidateAccessToken(JwtSecurityToken jwtToken, string accessToken, out TokenIdentity tokenIdentity)
    {
        tokenIdentity = new TokenIdentity();

        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = false,
            ValidAudiences = [_configuration.Audience],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };
        try
        {
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            jwtSecurityTokenHandler.ValidateToken(
                accessToken,
                validationParameters,
                out SecurityToken validatedToken);

            if (validatedToken is not JwtSecurityToken)
            {
                return false;
            }
        }
        catch (SecurityTokenException)
        {
            return false;
        }

        var userId = jwtToken.Subject;
        var scopes = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimType.Scope)?.Value?.Split(' ');

        tokenIdentity.UserId = userId;
        tokenIdentity.Scopes = scopes!;

        return true;
    }
}