using System.Security.Cryptography;

namespace Shark.AuthorizationServer.DomainServices.Services;

public static class Rsa256KeysGenerator
{
    public static void Generate(int keySizeInBits = 2048)
    {
        using var rsa = RSA.Create(keySizeInBits);

        var privateKeyPem = ExportRsaPrivateKeyPem(rsa);
        File.WriteAllText("Keys/RS256.Private.pem", privateKeyPem);

        var publicKeyPem = ExportRsaPublicKeyPem(rsa);
        File.WriteAllText("Keys/RS256.Public.pem", publicKeyPem);
    }

    private static string ExportRsaPrivateKeyPem(RSA rsa)
    {
        var privateKey = rsa.ExportRSAPrivateKey();
        return ConvertToPem(privateKey, "RSA PRIVATE KEY");
    }

    private static string ExportRsaPublicKeyPem(RSA rsa)
    {
        var publicKey = rsa.ExportRSAPublicKey();
        return ConvertToPem(publicKey, "RSA PUBLIC KEY");
    }

    private static string ConvertToPem(byte[] keyData, string keyType)
    {
        var base64 = Convert.ToBase64String(keyData, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {keyType}-----\n{base64}\n-----END {keyType}-----";
    }
}