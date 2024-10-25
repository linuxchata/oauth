using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IRegisterApplicationService
{
    Task<IRegisterInternalResponse> Read(string clientId);

    Task<IRegisterInternalResponse> Post(RegisterInternalRequest request);

    Task<IRegisterInternalResponse> Put(string clientId, RegisterUpdateInternalRequest request);

    Task<IRegisterInternalResponse> Delete(string clientId);
}