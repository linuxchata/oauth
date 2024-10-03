using System.Security.Cryptography;
using System.Text;
using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.Constants;

namespace Shark.AuthorizationServer.Services;

public sealed class ProofKeyForCodeExchangeService : IProofKeyForCodeExchangeService
{
    public string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(codeVerifier);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(codeChallengeMethod);

        if (!string.Equals(codeChallengeMethod, CodeChallengeMethod.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Unknown code challenge method");
        }

        return GetCodeChallenge(codeVerifier);
    }

    private string GetCodeChallenge(string codeVerifier)
    {
        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    private string Base64UrlEncode(byte[] input)
    {
        // Convert to base64, then replace URL-unsafe characters and trim padding.
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}