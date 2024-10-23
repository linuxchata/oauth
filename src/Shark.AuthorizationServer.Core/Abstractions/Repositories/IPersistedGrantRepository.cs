using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IPersistedGrantRepository :
    IRepositoryGet<PersistedGrant>,
    IRepositoryAdd<PersistedGrant>,
    IRepositoryAdd<DevicePersistedGrant>,
    IRepositoryRemove<PersistedGrant>
{
}