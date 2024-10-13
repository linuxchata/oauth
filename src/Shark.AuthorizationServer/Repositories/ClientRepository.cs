using Newtonsoft.Json;
using Shark.AuthorizationServer.Abstractions.Repositories;
using Shark.AuthorizationServer.Abstractions.Services;

namespace Shark.AuthorizationServer.Repositories;

public sealed class ClientRepository(IClientStore clientStore) : IClientRepository
{
    private readonly IClientStore _clientStore = clientStore;

    public Models.Client? GetById(string? id)
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
        _clientStore.Add(client);
    }
}