using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IConfigurationApplicationService
{
    ConfigurationResponse Get(string scheme, string host, int port);

    ConfigurationJwksResponse GetJsonWebKeySet();
}