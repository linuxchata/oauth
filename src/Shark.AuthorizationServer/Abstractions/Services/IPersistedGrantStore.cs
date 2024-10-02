using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IPersistedGrantStore : IStore<PersistedGrant>
{
}