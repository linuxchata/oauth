using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Revoke;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IRevokeApplicationService
{
    Task<IRevokeInternalResponse> Execute(RevokeInternalRequest request);
}