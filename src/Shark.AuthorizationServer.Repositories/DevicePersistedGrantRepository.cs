using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories.InMemory;

public sealed class DevicePersistedGrantRepository(IDistributedCache cache) : IDevicePersistedGrantRepository
{
    private const string Prefix = "device_grant_";

    private readonly IDistributedCache _cache = cache;

    public async Task<DevicePersistedGrant?> GetByUserCode(string? value)
    {
        return await GetInternal(value);
    }

    public async Task<DevicePersistedGrant?> GetByDeviceCode(string? value)
    {
        return await GetInternal(value);
    }

    public async Task Add(DevicePersistedGrant item)
    {
        var cacheEntryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = item.CreatedDate.AddSeconds(item.ExpiredIn),
        };

        var serializedItem = JsonSerializer.Serialize(item);

        await _cache.SetStringAsync(GetKey(item.UserCode), serializedItem, cacheEntryOptions);
        await _cache.SetStringAsync(GetKey(item.DeviceCode), serializedItem, cacheEntryOptions);
    }

    public async Task Update(DevicePersistedGrant item, bool isAuthorized)
    {
        var adjustedItem = item with { };
        adjustedItem.IsAuthorized = isAuthorized;

        await Remove(item);
        await Add(adjustedItem);
    }

    public async Task Remove(DevicePersistedGrant item)
    {
        if (!string.IsNullOrWhiteSpace(item.UserCode))
        {
            await _cache.RemoveAsync(GetKey(item.UserCode));
        }

        if (!string.IsNullOrWhiteSpace(item.DeviceCode))
        {
            await _cache.RemoveAsync(GetKey(item.DeviceCode));
        }
    }

    private async Task<DevicePersistedGrant?> GetInternal(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = await _cache.GetStringAsync(GetKey(value));

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<DevicePersistedGrant>(serializedItem);
        }

        return null;
    }

    private string GetKey(string key)
    {
        return $"{Prefix}{key}";
    }
}