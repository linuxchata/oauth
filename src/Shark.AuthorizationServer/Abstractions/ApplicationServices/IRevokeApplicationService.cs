using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Abstractions.ApplicationServices;

public interface IRevokeApplicationService
{
    RevokeInternalBaseResponse Execute(RevokeInternalRequest request);
}