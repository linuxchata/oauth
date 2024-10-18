using Shark.AuthorizationServer.Core.Responses.Configuration;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IConfigurationApplicationService
{
    Task<ConfigurationResponse> Get();

    Task<ConfigurationJwksResponse> GetJsonWebKeySet();
}