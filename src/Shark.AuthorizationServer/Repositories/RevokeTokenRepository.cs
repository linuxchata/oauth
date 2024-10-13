using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Repositories;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Repositories;

public sealed class RevokeTokenRepository(IDistributedCache cache) : IRevokeTokenRepository
{
    private readonly IDistributedCache _cache = cache;

    public RevokeToken? Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = _cache.GetString(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonConvert.DeserializeObject<RevokeToken>(serializedItem);
        }

        return null;
    }

    public void Add(RevokeToken item)
    {
        var serializedItem = JsonConvert.SerializeObject(item);
        _cache.SetString(item.TokenId, serializedItem);
    }
}