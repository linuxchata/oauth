using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Repositories;
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
            return JsonConvert.DeserializeObject<PersistedGrant>(serializedItem);
        }

        return null;
    }

    public void Add(PersistedGrant item)
    {
        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(item.ExpiredIn),
        };
        var serializedItem = JsonConvert.SerializeObject(item);
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