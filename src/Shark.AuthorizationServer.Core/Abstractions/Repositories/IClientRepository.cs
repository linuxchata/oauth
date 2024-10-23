using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IClientRepository
{
    Task<Client?> Get(string? value);

    Task Add(Client client);

    Task Remove(string? value);
}