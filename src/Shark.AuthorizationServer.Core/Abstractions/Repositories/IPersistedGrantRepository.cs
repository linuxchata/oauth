using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IPersistedGrantRepository
{
    Task<PersistedGrant?> GetByValue(string? value);

    Task<PersistedGrant?> GetByAccessTokenId(string? value);

    Task Add(PersistedGrant item);

    Task Remove(PersistedGrant item);
}