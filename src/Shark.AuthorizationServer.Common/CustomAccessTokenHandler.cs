using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Abstractions;

namespace Shark.AuthorizationServer.Common;

public sealed class CustomAccessTokenHandler(
    SecurityKey securityKey,
    ICertificateValidator certificateValidator,
    ILogger<CustomAccessTokenHandler> logger) : ICustomAccessTokenHandler
{
    private readonly SecurityKey _securityKey = securityKey;
    private readonly ICertificateValidator _certificateValidator = certificateValidator;
    private readonly ILogger<CustomAccessTokenHandler> _logger = logger;

    public JwtSecurityToken? Read(string accessToken, TokenValidationParameters? tokenValidationParameters)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(accessToken))
        {
            _logger.LogWarning("Token is not a well formed access token");
            return null;
        }

        var jwtToken = handler.ReadJwtToken(accessToken);
        if (tokenValidationParameters != null &&
            !ValidateAccessToken(handler, accessToken, tokenValidationParameters))
        {
            _logger.LogWarning("Token is not a valid access token");
            return null;
        }

        return jwtToken;
    }

    private bool ValidateAccessToken(
        JwtSecurityTokenHandler handler,
        string accessToken,
        TokenValidationParameters tokenValidationParameters)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = tokenValidationParameters.ValidateIssuer,
            ValidIssuer = tokenValidationParameters.ValidIssuer,
            ValidateAudience = tokenValidationParameters.ValidateAudience,
            ValidAudiences = tokenValidationParameters.ValidAudiences,
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