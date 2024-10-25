using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class ProofKeyForCodeExchangeService(
    IStringGeneratorService stringGeneratorService,
    IDistributedCache cache) : IProofKeyForCodeExchangeService
{
    private const string CodeChallengeMethod = "S256";
    private const int ExpirationInSeconds = 60;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IDistributedCache _cache = cache;

    public ProofKeyForCodeExchange Generate(string? state)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(state, nameof(state));

        var codeVerifier = _stringGeneratorService.GenerateCodeVerifier();
        var codeChallenge = GetCodeChallenge(codeVerifier);

        var pkce = new ProofKeyForCodeExchange
        {
            CodeVerifier = codeVerifier,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = CodeChallengeMethod,
        };

        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(ExpirationInSeconds),
        };
        var serializedPkce = JsonSerializer.Serialize(pkce);
        _cache.SetString(GetKey(state), serializedPkce, cacheEntryOptions);

        return pkce;
    }

    public ProofKeyForCodeExchange? Get(string? state)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(state, nameof(state));

        var serializedPkce = _cache.GetString(GetKey(state));

        if (!string.IsNullOrWhiteSpace(serializedPkce))
        {
            return JsonSerializer.Deserialize<ProofKeyForCodeExchange>(serializedPkce);
        }

        return null;
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

    private static string GetKey(string state)
    {
        return $"pkce_{state}";
    }
}