using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IRevokeTokenRepository : IRepositoryGet<RevokeToken>, IRepositoryAdd<RevokeToken>
{
}