using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

public interface IPublicKeyProvider
{
    Task<ConfigurationJwksResponse> Get();
}