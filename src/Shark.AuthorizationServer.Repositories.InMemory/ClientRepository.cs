﻿using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories.InMemory;

public sealed class ClientRepository(IDistributedCache cache) : IClientRepository
{
    private const string Prefix = "client_";

    private readonly IDistributedCache _cache = cache;

    public async Task<Client?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var serializedItem = await _cache.GetStringAsync(GetKey(value));

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<Client>(serializedItem);
        }

        return null;
    }

    public async Task Add(Client client)
    {
        ArgumentNullException.ThrowIfNull(client, nameof(client));

        var serializedItem = JsonSerializer.Serialize(client);

        await _cache.SetStringAsync(GetKey(client.ClientId), serializedItem);
    }

    public async Task Remove(string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            await _cache.RemoveAsync(GetKey(value));
        }
    }

    private static string GetKey(string key)
    {
        return $"{Prefix}{key}";
    }
}