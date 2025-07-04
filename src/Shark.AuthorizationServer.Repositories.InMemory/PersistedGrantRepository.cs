using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories.InMemory;

public sealed class PersistedGrantRepository(IDistributedCache cache) : IPersistedGrantRepository
{
    private const string Prefix = "grant_";

    private static readonly SemaphoreSlim _operationLock = new(1, 1);

    private readonly IDistributedCache _cache = cache;

    public async Task<PersistedGrant?> GetByValue(string? value)
    {
        return await GetInternal(value);
    }

    public async Task<PersistedGrant?> GetByAccessTokenId(string? value)
    {
        return await GetInternal(value);
    }

    public async Task Add(PersistedGrant item)
    {
        ArgumentNullException.ThrowIfNull(item, nameof(item));

        await _operationLock.WaitAsync();

        try
        {
            var cacheEntryOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = item.CreatedDate.AddSeconds(item.ExpiredIn),
            };

            var serializedItem = JsonSerializer.Serialize(item);

            await _cache.SetStringAsync(GetKey(item.Value), serializedItem, cacheEntryOptions);

            // Revoke token logic require to revoke refresh token with access token. Thefore
            // it must be possible to find refresh token persisted grant by access token identifier
            if (!string.IsNullOrWhiteSpace(item.AccessTokenId))
            {
                await _cache.SetStringAsync(GetKey(item.AccessTokenId), serializedItem, cacheEntryOptions);
            }
        }
        finally
        {
            _operationLock.Release();
        }
    }

    public async Task Remove(PersistedGrant item)
    {
        if (item == null)
        {
            return;
        }

        await _operationLock.WaitAsync();

        try
        {
            if (!string.IsNullOrWhiteSpace(item.Value))
            {
                await _cache.RemoveAsync(GetKey(item.Value));
            }

            if (!string.IsNullOrWhiteSpace(item.AccessTokenId))
            {
                await _cache.RemoveAsync(GetKey(item.AccessTokenId));
            }
        }
        finally
        {
            _operationLock.Release();
        }
    }

    private async Task<PersistedGrant?> GetInternal(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = await _cache.GetStringAsync(GetKey(value));

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<PersistedGrant>(serializedItem);
        }

        return null;
    }

    private static string GetKey(string key)
    {
        return $"{Prefix}{key}";
    }
}