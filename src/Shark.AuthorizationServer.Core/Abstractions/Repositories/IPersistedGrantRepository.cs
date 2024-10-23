using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IPersistedGrantRepository
{
    Task<PersistedGrant?> Get(string? value);

    Task Add(PersistedGrant item);

    Task Remove(string? value);
}