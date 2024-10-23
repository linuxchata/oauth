using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class DevicePersistedGrantRepository(IDistributedCache cache) : IDevicePersistedGrantRepository
{
    private readonly IDistributedCache _cache = cache;

    public async Task<DevicePersistedGrant?> GetByUserCode(string? value)
    {
        return await GetInternal<DevicePersistedGrant?>(value);
    }

    public async Task<DevicePersistedGrant?> GetByDeviceCode(string? value)
    {
        return await GetInternal<DevicePersistedGrant?>(value);
    }

    public async Task Add(DevicePersistedGrant item)
    {
        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = DateTime.Now.AddSeconds(item.ExpiredIn),
        };

        var serializedItem = JsonSerializer.Serialize(item);

        await _cache.SetStringAsync(item.UserCode, serializedItem, cacheEntryOptions);
        await _cache.SetStringAsync(item.DeviceCode, serializedItem, cacheEntryOptions);
    }

    public async Task Remove(DevicePersistedGrant item)
    {
        if (!string.IsNullOrWhiteSpace(item.UserCode))
        {
            await _cache.RemoveAsync(item.UserCode);
        }

        if (!string.IsNullOrWhiteSpace(item.DeviceCode))
        {
            await _cache.RemoveAsync(item.DeviceCode);
        }
    }

    private async Task<T?> GetInternal<T>(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return default;
        }

        var serializedItem = await _cache.GetStringAsync(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<T>(serializedItem);
        }

        return default;
    }
}