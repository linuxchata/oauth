using System.Security.Cryptography;
using System.Text;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices;

public sealed class ProofKeyForCodeExchangeService : IProofKeyForCodeExchangeService
{
    public string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier, nameof(codeVerifier));
        ArgumentException.ThrowIfNullOrWhiteSpace(codeChallengeMethod, nameof(codeChallengeMethod));

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