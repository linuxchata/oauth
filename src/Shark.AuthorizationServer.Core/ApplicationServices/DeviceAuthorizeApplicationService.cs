using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class DeviceAuthorizeApplicationService : IDeviceAuthorizeApplicationService
{
    public Task<DeviceAuthorizeBaseResponse> Execute(DeviceAuthorizeInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(nameof(request));

        var result = new DeviceAuthorizeResponse
        {
            DeviceCode = string.Empty,
            UserCode = string.Empty,
            VerificationUri = string.Empty,
            VerificationUriComplete = string.Empty,
            ExpiresIn = 0,
            Interval = 0,
        };

        return Task.FromResult(result as DeviceAuthorizeBaseResponse);
    }
}