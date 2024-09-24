using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public sealed class InMemoryPersistedGrantStore : IPersistedGrantStore
{
    private readonly IDistributedCache _cache;

    public InMemoryPersistedGrantStore(IDistributedCache cache)
    {
        _cache = cache;
    }

    public PersistedGrant? Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = _cache.GetString(value);
        var item = JsonConvert.DeserializeObject<PersistedGrant>(serializedItem!);

        return item;
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
}