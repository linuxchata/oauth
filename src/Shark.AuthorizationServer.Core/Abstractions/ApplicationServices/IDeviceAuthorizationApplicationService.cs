using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IDeviceAuthorizationApplicationService
{
    Task<IDeviceAuthorizationResponse> Execute(DeviceAuthorizationInternalRequest request);
}
