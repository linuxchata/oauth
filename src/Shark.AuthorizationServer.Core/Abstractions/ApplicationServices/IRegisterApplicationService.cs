using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IRegisterApplicationService
{
    RegisterInternalBaseResponse Read(string clientId);

    RegisterInternalBaseResponse Post(RegisterInternalRequest request);

    RegisterInternalBaseResponse Put(string clientId, RegisterUpdateInternalRequest request);

    RegisterInternalBaseResponse Delete(string clientId);
}