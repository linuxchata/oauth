using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IConfigurationJwksProvider
{
    Task<ConfigurationJwksResponse> Get();
}