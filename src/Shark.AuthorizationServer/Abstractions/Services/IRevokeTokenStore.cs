using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IRevokeTokenStore : IStoreGet<RevokeToken>, IStoreAdd<RevokeToken>
{
}