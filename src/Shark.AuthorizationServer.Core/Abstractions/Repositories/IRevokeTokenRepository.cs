using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRevokeTokenRepository : IRepositoryGet<RevokeToken>, IRepositoryAdd<RevokeToken>
{
}