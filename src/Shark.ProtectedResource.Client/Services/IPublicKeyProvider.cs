using Shark.ProtectedResource.Client.Models;

namespace Shark.ProtectedResource.Client.Services;

public interface IPublicKeyProvider
{
    Task<ConfigurationJwksResponse> Get();
}