using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public interface IPublicKeyProvider
{
    Task<ConfigurationJwksResponse> Get();
}