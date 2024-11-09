using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class SigningCredentialsService(
    ICertificateValidator certificateValidator,
    IOptions<AuthorizationServerSecurityConfiguration> options,
    [FromKeyedServices("private")] RsaSecurityKey? rsaSecurityKey = null,
    [FromKeyedServices("private")] X509SecurityKey? x509SecurityKey = null,
    SymmetricSecurityKey? symmetricSecurityKey = null) : ISigningCredentialsService
{
    private readonly ICertificateValidator _certificateValidator = certificateValidator;
    private readonly RsaSecurityKey? _rsaSecurityKey = rsaSecurityKey;
    private readonly X509SecurityKey? _x509SecurityKey = x509SecurityKey;
    private readonly SymmetricSecurityKey? _symmetricSecurityKey = symmetricSecurityKey;
    private readonly AuthorizationServerSecurityConfiguration _configuration = options.Value;

    public SigningCredentials GetSigningCredentials()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            if (_configuration.UseRsaCertificate)
            {
                return GetX509SigningCredentials(_x509SecurityKey);
            }
            else
            {
                return GetRsaSigningCredentials(_rsaSecurityKey);
            }
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GetSymmetricSigningCredentials();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }

    private SigningCredentials GetX509SigningCredentials(X509SecurityKey? securityKey)
    {
        if (securityKey is null)
        {
            throw new InvalidOperationException("X509 security key must not be null");
        }

        if (securityKey.Certificate is null)
        {
            throw new InvalidOperationException("X509 certificate must not be null");
        }

        if (!_certificateValidator.IsValid(securityKey.Certificate))
        {
            throw new InvalidOperationException("X509 certificate must be valid");
        }

        return GetSigningCredentials(securityKey);
    }

    private SigningCredentials GetRsaSigningCredentials(RsaSecurityKey? securityKey)
    {
        if (securityKey is null)
        {
            throw new InvalidOperationException("RSA security key must not be null");
        }

        return GetSigningCredentials(securityKey);
    }

    private SigningCredentials GetSymmetricSigningCredentials()
    {
        if (_symmetricSecurityKey is null)
        {
            throw new InvalidOperationException("Symmetric security key must not be null");
        }

        return new SigningCredentials(_symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
    }

    private SigningCredentials GetSigningCredentials(SecurityKey? securityKey)
    {
        return new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
        };
    }
}