using System.Security.Cryptography;
using System.Text;

namespace Shark.AuthorizationServer.Common;

public sealed class ProofKeyForCodeExchangeProvider
{
    public static string GetCodeChallenge(string codeVerifier)
    {
        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    public static string Base64UrlEncode(byte[] input)
    {
        // Convert to base64, then replace URL-unsafe characters and trim padding.
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
