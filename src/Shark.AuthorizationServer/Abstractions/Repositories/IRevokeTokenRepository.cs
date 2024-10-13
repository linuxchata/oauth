using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IRevokeTokenRepository : IRepositoryGet<RevokeToken>, IRepositoryAdd<RevokeToken>
{
}