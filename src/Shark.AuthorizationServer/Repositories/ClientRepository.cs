using Newtonsoft.Json;

namespace Shark.AuthorizationServer.Repositories;

public sealed class ClientRepository : IClientRepository
{
    public Models.Client? GetById(string id)
    {
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
}