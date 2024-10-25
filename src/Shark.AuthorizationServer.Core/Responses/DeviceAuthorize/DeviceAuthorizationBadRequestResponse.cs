namespace Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

public sealed class DeviceAuthorizationBadRequestResponse(string message) : IDeviceAuthorizationResponse
{
    public string Message { get; init; } = message;
}