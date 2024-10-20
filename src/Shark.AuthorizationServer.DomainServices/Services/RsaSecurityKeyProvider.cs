using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.DomainServices.Services;

public static class RsaSecurityKeyProvider
{
    public static RsaSecurityKey GetFromPublicKey(string keyPath)
    {
        ArgumentNullException.ThrowIfNull(keyPath, nameof(keyPath));

        var rsaSecurityKey = GetRsaSecurityKey(keyPath);

        if (rsaSecurityKey.PrivateKeyStatus == PrivateKeyStatus.Exists)
        {
            throw new InvalidOperationException("Public RSA security key must not have private key");
        }

        return rsaSecurityKey;
    }

    public static RsaSecurityKey GetFromPrivateKey(string keyPath)
    {
        ArgumentNullException.ThrowIfNull(keyPath, nameof(keyPath));

        var rsaSecurityKey = GetRsaSecurityKey(keyPath);

        if (rsaSecurityKey.PrivateKeyStatus != PrivateKeyStatus.Exists)
        {
            throw new InvalidOperationException("Private RSA security key must have private key");
        }

        return rsaSecurityKey;
    }

    public static RsaSecurityKey GetFromPublicCertificate(string certificatePath)
    {
        ArgumentNullException.ThrowIfNull(certificatePath, nameof(certificatePath));

        var certificate = new X509Certificate2(certificatePath);

        var rsa = certificate.GetRSAPublicKey()
            ?? throw new InvalidOperationException("Ceritifate does not have RSA public key");

        return new RsaSecurityKey(rsa);
    }

    public static RsaSecurityKey GetFromPrivateCertificate(string certificatePath, string certificatePassword)
    {
        ArgumentNullException.ThrowIfNull(certificatePath, nameof(certificatePath));
        ArgumentNullException.ThrowIfNull(certificatePassword, nameof(certificatePassword));

        var certificate = new X509Certificate2(certificatePath, certificatePassword);

        var rsa = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Ceritifate does not have RSA private key");

        return new RsaSecurityKey(rsa);
    }

    private static RsaSecurityKey GetRsaSecurityKey(string keyPath)
    {
        var key = File.ReadAllText(keyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(key);

        return new RsaSecurityKey(rsa);
    }
}