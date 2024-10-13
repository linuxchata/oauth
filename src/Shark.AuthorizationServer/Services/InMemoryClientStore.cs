using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public sealed class InMemoryClientStore(IDistributedCache cache) : IClientStore
{
    private readonly IDistributedCache _cache = cache;

    public void Add(Client item)
    {
        var serializedItem = JsonConvert.SerializeObject(item);
        _cache.SetString(item.ClientId, serializedItem);
    }
}