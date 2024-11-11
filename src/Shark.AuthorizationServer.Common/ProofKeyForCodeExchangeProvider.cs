using System.Security.Cryptography;
using System.Text;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;

namespace Shark.AuthorizationServer.Common;

public static class ProofKeyForCodeExchangeProvider
{
    public static string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        if (codeChallengeMethod.EqualsTo(CodeChallengeMethod.Plain))
        {
            return codeVerifier;
        }
        else if (codeChallengeMethod.EqualsTo(CodeChallengeMethod.Sha256))
        {
            var bytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hash = SHA256.HashData(bytes);
            return Base64UrlEncode(hash);
        }
        else
        {
            throw new ArgumentException($"Unsupported code challenge method [{codeChallengeMethod}]");
        }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        // Convert to base64, then replace URL-unsafe characters and trim padding.
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
