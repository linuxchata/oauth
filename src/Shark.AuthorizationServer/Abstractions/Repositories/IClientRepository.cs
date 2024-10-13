using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IClientRepository : IRepositoryGet<Client>, IRepositoryAdd<Client>, IRepositoryRemove<Client>
{
}