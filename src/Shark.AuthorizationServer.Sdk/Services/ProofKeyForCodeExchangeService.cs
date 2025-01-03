﻿using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class ProofKeyForCodeExchangeService(
    IStringGeneratorService stringGeneratorService,
    IDistributedCache cache) : IProofKeyForCodeExchangeService
{
    private const int ExpirationInSeconds = 60;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IDistributedCache _cache = cache;

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

    public ProofKeyForCodeExchange Generate(string? state, string codeChallengeMethod = CodeChallengeMethod.Sha256)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(state, nameof(state));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(codeChallengeMethod, nameof(codeChallengeMethod));

        if (!CodeChallengeMethod.Supported.Contains(codeChallengeMethod))
        {
            throw new ArgumentException($"Unsupported code challenge method [{codeChallengeMethod}]");
        }

        var codeVerifier = _stringGeneratorService.GenerateCodeVerifier();
        var codeChallenge = ProofKeyForCodeExchangeProvider.GetCodeChallenge(codeVerifier, codeChallengeMethod);

        var pkce = new ProofKeyForCodeExchange
        {
            CodeVerifier = codeVerifier,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
        };

        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(ExpirationInSeconds),
        };
        var serializedPkce = JsonSerializer.Serialize(pkce);
        _cache.SetString(GetKey(state), serializedPkce, cacheEntryOptions);

        return pkce;
    }

    private static string GetKey(string state)
    {
        return $"pkce_{state}";
    }
}