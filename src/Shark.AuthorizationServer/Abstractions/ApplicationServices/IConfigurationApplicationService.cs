using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Abstractions.ApplicationServices;

public interface IConfigurationApplicationService
{
    ConfigurationResponse Get(string scheme, string host, int port);

    ConfigurationJwksResponse GetJsonWebKeySet();
}