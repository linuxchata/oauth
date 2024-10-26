using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IRegisterApplicationService
{
    Task<IRegisterInternalResponse> ExecuteRead(string clientId);

    Task<IRegisterInternalResponse> ExecutePost(RegisterInternalRequest request);

    Task<IRegisterInternalResponse> ExecutePut(string clientId, RegisterUpdateInternalRequest request);

    Task<IRegisterInternalResponse> ExecuteDelete(string clientId);
}