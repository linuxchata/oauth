using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IRegisterApplicationService
{
    Task<RegisterInternalBaseResponse> Read(string clientId);

    Task<RegisterInternalBaseResponse> Post(RegisterInternalRequest request);

    Task<RegisterInternalBaseResponse> Put(string clientId, RegisterUpdateInternalRequest request);

    Task<RegisterInternalBaseResponse> Delete(string clientId);
}