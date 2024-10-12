using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IPersistedGrantStore :
    IStoreGet<PersistedGrant>,
    IStoreAdd<PersistedGrant>,
    IStoreRemove<PersistedGrant>
{
}