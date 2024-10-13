using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class PersistedGrantRepository(IDistributedCache cache) : IPersistedGrantRepository
{
    private readonly IDistributedCache _cache = cache;

    public PersistedGrant? Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = _cache.GetString(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<PersistedGrant>(serializedItem);
        }

        return null;
    }

    public void Add(PersistedGrant item)
    {
        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(item.ExpiredIn),
        };
        var serializedItem = JsonSerializer.Serialize(item);
        _cache.SetString(item.Value, serializedItem, cacheEntryOptions);
    }

    public void Remove(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        _cache.Remove(value);
    }
}