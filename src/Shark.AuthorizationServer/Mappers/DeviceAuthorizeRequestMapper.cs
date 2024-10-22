using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class DeviceAuthorizeRequestMapper
{
    public static DeviceAuthorizationInternalRequest ToInternalRequest(this DeviceAuthorizationRequest request)
    {
        return new DeviceAuthorizationInternalRequest
        {
            ClientId = request.client_id,
            Scope = request.scope,
        };
    }
}