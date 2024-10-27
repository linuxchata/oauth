using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IPublicKeyProvider
{
    Task<ConfigurationJwksResponse> Get();
}