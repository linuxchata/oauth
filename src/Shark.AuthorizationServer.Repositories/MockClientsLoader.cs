using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Repositories.InMemory;

public sealed class MockClientsLoader(IDistributedCache cache) : IMockClientsLoader
{
    private const string Prefix = "client_";

    private readonly IDistributedCache _cache = cache;

    public void Load()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var assemblyName = assembly.GetName().Name;
        var resourceName = $"{assemblyName}.Data.clients.json";

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Resource [{resourceName}] not found.");

        using var streamReader = new StreamReader(stream);
        var clients = streamReader.ReadToEnd();

        var deserializedClients = JsonSerializer.Deserialize<List<Client>>(clients);
        if (deserializedClients != null)
        {
            foreach (var client in deserializedClients)
            {
                var serializedItem = JsonSerializer.Serialize(client);
                _cache.SetString(GetKey(client.ClientId), serializedItem);
            }
        }
    }

    private string GetKey(string key)
    {
        return $"{Prefix}{key}";
    }
}