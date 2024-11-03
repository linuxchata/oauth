using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Configurations;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class BearerTokenHandlingService(
    SecurityKey securityKey,
    ICertificateValidator certificateValidator,
    IOptions<BearerTokenAuthenticationOptions> options,
    ILogger<BearerTokenHandlingService> logger) : IBearerTokenHandlingService
{
    private const string HeaderKeyName = "Authorization";

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

        if (!authorization.StartsWith(Scheme.Bearer, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var startIndexOfAccessToken = authorization.IndexOf(Scheme.Bearer) + 1;
        var accessToken = authorization[(startIndexOfAccessToken + Scheme.Bearer.Length)..];

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
        if (!ValidateAccessToken(handler, accessToken, ref tokenIdentity))
        {
            return false;
        }

        //// TODO: Add token inspection via the network and wrap it around configuration flag

        var userId = jwtToken.Subject;
        var scopes = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimType.Scope)?.Value?.Split(' ');

        tokenIdentity.UserId = userId;
        tokenIdentity.Scopes = scopes!;

        return true;
    }

    private bool ValidateAccessToken(
        JwtSecurityTokenHandler handler,
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
            _logger.LogError(ex, "{Message}", ex.Message);
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