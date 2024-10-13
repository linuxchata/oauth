using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IPersistedGrantRepository :
    IRepositoryGet<PersistedGrant>,
    IRepositoryAdd<PersistedGrant>,
    IRepositoryRemove<PersistedGrant>
{
}