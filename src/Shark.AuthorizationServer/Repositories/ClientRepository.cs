using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories;

public sealed class ClientRepository(IDistributedCache cache) : IClientRepository
{
    private readonly IDistributedCache _cache = cache;

    public Client? Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        // Read from cache
        var serializedItem = _cache.GetString(value);

        if (!string.IsNullOrWhiteSpace(serializedItem))
        {
            return JsonConvert.DeserializeObject<Client>(serializedItem);
        }

        // Read from file
        using var streamReader = new StreamReader("Data/clients.json");
        var clients = streamReader.ReadToEnd();
        var deserializedClients = JsonConvert.DeserializeObject<List<Client>>(clients);

        if (deserializedClients is not null)
        {
            return deserializedClients.FirstOrDefault(
                c => string.Equals(c.ClientId, value, StringComparison.OrdinalIgnoreCase));
        }

        throw new InvalidOperationException($"Client with identifier {value} cannot be found");
    }

    public void Add(Client client)
    {
        var serializedItem = JsonConvert.SerializeObject(client);
        _cache.SetString(client.ClientId, serializedItem);
    }

    public void Remove(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        _cache.Remove(value);
    }
}