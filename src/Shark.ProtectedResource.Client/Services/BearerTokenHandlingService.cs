using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

public sealed class BearerTokenHandlingService(
    Microsoft.IdentityModel.Tokens.RsaSecurityKey rsaSecurityKey,
    IOptions<BearerTokenAuthenticationOptions> options,
    ILogger<BearerTokenHandlingService> logger) : IBearerTokenHandlingService
{
    private const string HeaderKeyName = "Authorization";
    private const string BearerTokenName = "Bearer";

    private readonly Microsoft.IdentityModel.Tokens.RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;
    private readonly ILogger<BearerTokenHandlingService> _logger = logger;

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
        if (!handler.CanReadToken(accessToken))
        {
            return false;
        }

        var jwtToken = handler.ReadJwtToken(accessToken);
        if (!ValidateAccessToken(handler, jwtToken, accessToken, ref tokenIdentity))
        {
            return false;
        }

        var userId = jwtToken.Subject;
        var scopes = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimType.Scope)?.Value?.Split(' ');

        tokenIdentity.UserId = userId;
        tokenIdentity.Scopes = scopes!;

        return true;
    }

    private bool ValidateAccessToken(
        JwtSecurityTokenHandler handler,
        JwtSecurityToken jwtToken,
        string accessToken,
        ref TokenIdentity tokenIdentity)
    {
        tokenIdentity = new TokenIdentity();

        var securityKey = GetIssuerSigningKey(jwtToken.SignatureAlgorithm);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = _configuration.ValidateIssuer,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = _configuration.ValidateAudience,
            ValidAudiences = new List<string> { _configuration.Audience },
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(10),
        };

        try
        {
            handler.ValidateToken(accessToken, validationParameters, out SecurityToken validatedToken);
            if (!(validatedToken is JwtSecurityToken))
            {
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return false;
        }

        return true;
    }

    private SecurityKey GetIssuerSigningKey(string signatureAlgorithm)
    {
        if (signatureAlgorithm == SecurityAlgorithms.HmacSha256)
        {
            var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);

            return new SymmetricSecurityKey(key)
            {
                KeyId = _configuration.KeyId
            };
        }
        else if (signatureAlgorithm == SecurityAlgorithms.RsaSha256)
        {
            return _rsaSecurityKey;
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {signatureAlgorithm}");
    }
}