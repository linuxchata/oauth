using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    private static SecurityKey GetRsaSecurityKey(ConfigurationJwksResponse configurationJwksResponse)
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

        if (!string.IsNullOrWhiteSpace(configurationJwksResponse.X509CertificateChain))
        {
            var certificateBytes = Convert.FromBase64String(configurationJwksResponse.X509CertificateChain!);
            var certificate = new X509Certificate2(certificateBytes);

            var x509SecurityKey = new X509SecurityKey(certificate)
            {
                KeyId = configurationJwksResponse.KeyId,
            };

            return x509SecurityKey;
        }
        else
        {
            var rsaParams = new RSAParameters
            {
                Modulus = Convert.FromBase64String(configurationJwksResponse.Modulus!),
                Exponent = Convert.FromBase64String(configurationJwksResponse.Exponent!),
            };

            rsa.ImportParameters(rsaParams);

            var rsaSecurityKey = new RsaSecurityKey(rsa)
            {
                KeyId = configurationJwksResponse.KeyId,
            };

            return rsaSecurityKey;
        }
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