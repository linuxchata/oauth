using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

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
            return JsonSerializer.Deserialize<RevokeToken>(serializedItem);
        }

        return null;
    }

    public void Add(RevokeToken item)
    {
        var serializedItem = JsonSerializer.Serialize(item);
        _cache.SetString(item.TokenId, serializedItem);
    }
}