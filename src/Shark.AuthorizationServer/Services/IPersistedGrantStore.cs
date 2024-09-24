using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public interface IPersistedGrantStore : IStore<PersistedGrant>
{
}