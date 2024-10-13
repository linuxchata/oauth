using Shark.AuthorizationServer.Core.Responses;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IConfigurationApplicationService
{
    ConfigurationResponse Get();

    ConfigurationJwksResponse GetJsonWebKeySet();
}