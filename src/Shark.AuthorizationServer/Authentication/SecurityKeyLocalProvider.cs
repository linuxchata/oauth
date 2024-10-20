using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Services;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.Authentication;

/// <summary>
/// SecurityKey provider for authorization server itself.
/// </summary>
/// <param name="rsaSecurityKey">Represents a RSA security key.</param>
public sealed class SecurityKeyLocalProvider(
    IOptions<AuthorizationServerSecurityConfiguration> securityOptions,
    [FromKeyedServices("public")] RsaSecurityKey? rsaSecurityKey = null,
    SymmetricSecurityKey? symmetricSecurityKey = null) : ISecurityKeyProvider
{
    private readonly RsaSecurityKey? _rsaSecurityKey = rsaSecurityKey;
    private readonly SymmetricSecurityKey? _symmetricSecurityKey = symmetricSecurityKey;
    private readonly AuthorizationServerSecurityConfiguration _configuration = securityOptions.Value;

    public Task<SecurityKey> GetSecurityKey()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            var securityKey = _symmetricSecurityKey ??
                throw new InvalidOperationException("Symmetric security key is not registered");

            return Task.FromResult(securityKey as SecurityKey);
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            var securityKey = _rsaSecurityKey ??
                throw new InvalidOperationException("RSA security key is not registered");

            return Task.FromResult(securityKey as SecurityKey);
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }
}
