using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

/// <summary>
/// SecurityKey provider for authorization server clients.
/// </summary>
/// <param name="publicKeyProvider">Represents a public key provider.</param>
public sealed class SecurityKeyNetworkProvider(IPublicKeyProvider publicKeyProvider) : ISecurityKeyProvider
{
    private readonly IPublicKeyProvider _publicKeyProvider = publicKeyProvider;

    public async Task<SecurityKey> GetSecurityKey()
    {
        var configurationJwksResponse = await _publicKeyProvider.Get() ??
            throw new InvalidOperationException("JSON Web Key Set configuration is empty");

        if (configurationJwksResponse.Algorithm == SecurityAlgorithms.HmacSha256)
        {
            return GetSymmetricSecurityKey(configurationJwksResponse);
        }
        else if (configurationJwksResponse.Algorithm == SecurityAlgorithms.RsaSha256)
        {
            return GetRsaSecurityKey(configurationJwksResponse);
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {configurationJwksResponse.Algorithm}");
    }

    private static RsaSecurityKey GetRsaSecurityKey(ConfigurationJwksResponse configurationJwksResponse)
    {
        if (!string.Equals(configurationJwksResponse.KeyType, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Unssuported key type {configurationJwksResponse.KeyType}");
        }

        if (!string.Equals(configurationJwksResponse.Algorithm, SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Unssuported algorithm {configurationJwksResponse.Algorithm}");
        }

        var rsa = RSA.Create();

        var rsaParams = new RSAParameters
        {
            Modulus = Convert.FromBase64String(configurationJwksResponse.Modulus!),
            Exponent = Convert.FromBase64String(configurationJwksResponse.Exponent!),
        };

        rsa.ImportParameters(rsaParams);

        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = configurationJwksResponse.KeyId
        };

        return securityKey;
    }

    private static SymmetricSecurityKey GetSymmetricSecurityKey(ConfigurationJwksResponse configurationJwksResponse)
    {
        var key = Encoding.UTF8.GetBytes(configurationJwksResponse.SymmetricKey!);

        return new SymmetricSecurityKey(key)
        {
            KeyId = configurationJwksResponse.KeyId,
        };
    }
}