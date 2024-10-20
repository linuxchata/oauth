using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.DomainServices.Services;

public static class SecurityKeyProvider
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

    public static X509SecurityKey GetFromPublicCertificate(string certificatePath)
    {
        ArgumentNullException.ThrowIfNull(certificatePath, nameof(certificatePath));

        var certificate = new X509Certificate2(certificatePath);

        if (certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Ceritifate must not have a private key");
        }

        return new X509SecurityKey(certificate);
    }

    public static X509SecurityKey GetFromPrivateCertificate(string certificatePath, string certificatePassword)
    {
        ArgumentNullException.ThrowIfNull(certificatePath, nameof(certificatePath));
        ArgumentNullException.ThrowIfNull(certificatePassword, nameof(certificatePassword));

        var certificate = new X509Certificate2(certificatePath, certificatePassword);

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Ceritifate must have a private key");
        }

        return new X509SecurityKey(certificate);
    }

    private static RsaSecurityKey GetRsaSecurityKey(string keyPath)
    {
        var key = File.ReadAllText(keyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(key);

        return new RsaSecurityKey(rsa);
    }
}