using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Abstractions.ApplicationServices;

public interface IRegisterApplicationService
{
    RegisterInternalBaseResponse Read(string clientId);

    RegisterInternalBaseResponse Post(RegisterInternalRequest request);

    RegisterInternalBaseResponse Delete(string clientId);
}