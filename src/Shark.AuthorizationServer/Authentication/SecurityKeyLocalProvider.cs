using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;

namespace Shark.AuthorizationServer.Authentication;

/// <summary>
/// SecurityKey provider for authorization server itself.
/// </summary>
/// <param name="securityOptions">Security configuration.</param>
/// <param name="rsaSecurityKey">Represents a RSA security key.</param>
/// <param name="x509SecurityKey">Represents a x509 security key.</param>
/// <param name="symmetricSecurityKey">Represents a symmetric security key.</param>
public sealed class SecurityKeyLocalProvider(
    IOptions<AuthorizationServerSecurityConfiguration> securityOptions,
    [FromKeyedServices("public")] RsaSecurityKey? rsaSecurityKey = null,
    [FromKeyedServices("public")] X509SecurityKey? x509SecurityKey = null,
    SymmetricSecurityKey? symmetricSecurityKey = null) : ISecurityKeyProvider
{
    private readonly RsaSecurityKey? _rsaSecurityKey = rsaSecurityKey;
    private readonly X509SecurityKey? _x509SecurityKey = x509SecurityKey;
    private readonly SymmetricSecurityKey? _symmetricSecurityKey = symmetricSecurityKey;
    private readonly AuthorizationServerSecurityConfiguration _configuration = securityOptions.Value;

    public Task<SecurityKey> GetSecurityKey()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            if (_configuration.UseRsaCertificate)
            {
                return GetX509SecurityKey();
            }
            else
            {
                return GetRsaSecurityKey();
            }
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GetSymmetricSecurityKey();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }

    private Task<SecurityKey> GetX509SecurityKey()
    {
        var securityKey = _x509SecurityKey ??
            throw new InvalidOperationException("X509 security key is not registered");

        return Task.FromResult(securityKey as SecurityKey);
    }

    private Task<SecurityKey> GetRsaSecurityKey()
    {
        var securityKey = _rsaSecurityKey ??
            throw new InvalidOperationException("RSA security key is not registered");

        return Task.FromResult(securityKey as SecurityKey);
    }

    private Task<SecurityKey> GetSymmetricSecurityKey()
    {
        var securityKey = _symmetricSecurityKey ??
            throw new InvalidOperationException("Symmetric security key is not registered");

        return Task.FromResult(securityKey as SecurityKey);
    }
}
