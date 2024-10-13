using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Repositories;

namespace Shark.AuthorizationServer.Repositories;

public sealed class ClientRepository(IDistributedCache cache) : IClientRepository
{
    private readonly IDistributedCache _cache = cache;

    public Models.Client? Get(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        using var streamReader = new StreamReader("Data/clients.json");
        var clients = streamReader.ReadToEnd();
        var deserializedClients = JsonConvert.DeserializeObject<List<Models.Client>>(clients);

        if (deserializedClients is not null)
        {
            return deserializedClients.FirstOrDefault(
                c => string.Equals(c.ClientId, id, StringComparison.OrdinalIgnoreCase));
        }

        throw new Exception($"Client with identifier {id} cannot be found");
    }

    public void Add(Models.Client client)
    {
        var serializedItem = JsonConvert.SerializeObject(client);
        _cache.SetString(client.ClientId, serializedItem);
    }
}