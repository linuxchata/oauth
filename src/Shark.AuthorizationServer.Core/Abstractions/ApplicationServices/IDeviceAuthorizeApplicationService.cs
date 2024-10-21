using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IDeviceAuthorizeApplicationService
{
    Task<DeviceAuthorizeBaseResponse> Execute(DeviceAuthorizeInternalRequest request);
}
