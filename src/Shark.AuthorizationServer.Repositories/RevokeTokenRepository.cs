using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class RevokeTokenRepository(IDistributedCache cache) : IRevokeTokenRepository
{
    private readonly IDistributedCache _cache = cache;

    public async Task<RevokeToken?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = await _cache.GetStringAsync(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<RevokeToken>(serializedItem);
        }

        return null;
    }

    public async Task Add(RevokeToken item)
    {
        var serializedItem = JsonSerializer.Serialize(item);
        await _cache.SetStringAsync(item.TokenId, serializedItem);
    }
}