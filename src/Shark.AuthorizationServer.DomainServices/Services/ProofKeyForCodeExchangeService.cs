using System.Security.Cryptography;
using System.Text;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class ProofKeyForCodeExchangeService : IProofKeyForCodeExchangeService
{
    public string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier, nameof(codeVerifier));
        ArgumentException.ThrowIfNullOrWhiteSpace(codeChallengeMethod, nameof(codeChallengeMethod));

        if (!codeChallengeMethod.EqualsTo(CodeChallengeMethod.Sha256))
        {
            throw new ArgumentException("Unknown code challenge method");
        }

        return GetCodeChallenge(codeVerifier);
    }

    private static string GetCodeChallenge(string codeVerifier)
    {
        var bytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
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