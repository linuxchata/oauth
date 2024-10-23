using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class ClientRepository(IDistributedCache cache) : IClientRepository
{
    private readonly IDistributedCache _cache = cache;

    public async Task<Client?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        // Read from cache
        var serializedItem = await _cache.GetStringAsync(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonSerializer.Deserialize<Client>(serializedItem);
        }

        // Read from file
        using var streamReader = new StreamReader("Data/clients.json");
        var clients = streamReader.ReadToEnd();
        var deserializedClients = JsonSerializer.Deserialize<List<Client>>(clients);

        if (deserializedClients is not null)
        {
            return deserializedClients.FirstOrDefault(c => c.ClientId.EqualsTo(value));
        }

        throw new InvalidOperationException($"Client with identifier {value} cannot be found");
    }

    public async Task Add(Client client)
    {
        var serializedItem = JsonSerializer.Serialize(client);

        await _cache.SetStringAsync(client.ClientId, serializedItem);
    }

    public async Task Remove(string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            await _cache.RemoveAsync(value);
        }
    }
}