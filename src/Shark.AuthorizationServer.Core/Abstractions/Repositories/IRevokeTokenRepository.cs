using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRevokeTokenRepository
{
    Task<RevokeToken?> Get(string? value);

    Task Add(RevokeToken item);
}