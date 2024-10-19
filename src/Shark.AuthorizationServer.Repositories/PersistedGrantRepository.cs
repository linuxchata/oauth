using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class PersistedGrantRepository(IDistributedCache cache) : IPersistedGrantRepository
{
    private readonly IDistributedCache _cache = cache;

    public async Task<PersistedGrant?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = await _cache.GetStringAsync(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<PersistedGrant>(serializedItem);
        }

        return null;
    }

    public async Task Add(PersistedGrant item)
    {
        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(item.ExpiredIn),
        };
        var serializedItem = JsonSerializer.Serialize(item);
        await _cache.SetStringAsync(item.Value, serializedItem, cacheEntryOptions);
    }

    public async Task Remove(string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            await _cache.RemoveAsync(value);
        }
    }
}