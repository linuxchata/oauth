using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Client.Models;
using Shark.AuthorizationServer.Common.Abstractions;

namespace Shark.AuthorizationServer.Client.Services;

public sealed class BearerTokenHandlingService(
    SecurityKey securityKey,
    ICertificateValidator certificateValidator,
    IOptions<BearerTokenAuthenticationOptions> options,
    ILogger<BearerTokenHandlingService> logger) : IBearerTokenHandlingService
{
    private const string HeaderKeyName = "Authorization";
    private const string BearerTokenName = "Bearer";

    private readonly SecurityKey _securityKey = securityKey;
    private readonly ICertificateValidator _certificateValidator = certificateValidator;
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

        // TODO: Add token inspection via the network and wrap it around configuration flag

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

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = _configuration.ValidateIssuer,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = _configuration.ValidateAudience,
            ValidAudiences = [_configuration.Audience],
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyValidator = IssuerSigningKeyValidator(),
            IssuerSigningKey = _securityKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(10),
        };

        try
        {
            handler.ValidateToken(accessToken, validationParameters, out SecurityToken validatedToken);
            if (validatedToken is not JwtSecurityToken)
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

    private IssuerSigningKeyValidator IssuerSigningKeyValidator()
    {
        return (securityKey, securityToken, validationParameters) =>
        {
            if (securityKey is X509SecurityKey x509SecurityKey)
            {
                return _certificateValidator.IsValid(x509SecurityKey.Certificate);
            }

            return true;
        };
    }
}