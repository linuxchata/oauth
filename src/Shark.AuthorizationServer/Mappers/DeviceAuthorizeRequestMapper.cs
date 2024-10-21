using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class DeviceAuthorizeRequestMapper
{
    public static DeviceAuthorizeInternalRequest ToInternalRequest(this DeviceAuthorizeRequest request)
    {
        return new DeviceAuthorizeInternalRequest
        {
            ClientId = request.client_id,
            Scope = request.scope,
        };
    }
}