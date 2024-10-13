using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class SecureTokenStore(IDistributedCache cache) : ISecureTokenStore
{
    private readonly IDistributedCache _cache = cache;

    public string? GetAccessToken(string key)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));

        var secureToken = GetSecureToken(key);

        return secureToken?.AccessToken;
    }

    public string? GetRefreshToken(string key)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));

        var secureToken = GetSecureToken(key);

        return secureToken?.RefreshToken;
    }

    public void Add(string key, SecureToken secureToken)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));
        ArgumentNullException.ThrowIfNull(secureToken, nameof(secureToken));

        var serializedItem = JsonSerializer.Serialize(secureToken);
        _cache.SetString(key, serializedItem);
    }

    public void RemoveAccessToken(string key)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(key, nameof(key));

        var secureToken = GetSecureToken(key);

        if (secureToken != null)
        {
            var updatedSecureToken = new SecureToken(null, secureToken.RefreshToken);

            Add(key, updatedSecureToken);
        }
    }

    private SecureToken? GetSecureToken(string key)
    {
        var serializedItem = _cache.GetString(key);
        if(serializedItem != null)
        {
            return JsonSerializer.Deserialize<SecureToken>(serializedItem!);
        }

        return null;
    }
}
