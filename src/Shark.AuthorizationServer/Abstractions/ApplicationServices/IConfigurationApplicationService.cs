using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Abstractions.ApplicationServices;

public interface IConfigurationApplicationService
{
    ConfigurationResponse Get();

    ConfigurationJwksResponse GetJsonWebKeySet();
}