using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

public sealed class RsaSecurityKeyProvider(IPublicKeyProvider publicKeyProvider) : IRsaSecurityKeyProvider
{
    private readonly IPublicKeyProvider _publicKeyProvider = publicKeyProvider;

    public async Task<RsaSecurityKey> GetRsaSecurityKey()
    {
        var configurationJwksResponse =
            await _publicKeyProvider.Get() ??
            throw new InvalidOperationException("JSON Web Key Set configuration is empty");

        return GetRsaSecurityKey(configurationJwksResponse);
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
            Modulus = Convert.FromBase64String(configurationJwksResponse.Modulus),
            Exponent = Convert.FromBase64String(configurationJwksResponse.Exponent),
        };

        rsa.ImportParameters(rsaParams);

        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = configurationJwksResponse.KeyId
        };

        return securityKey;
    }
}