namespace Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

public sealed class DeviceAuthorizationBadRequestResponse(string message) : DeviceAuthorizationBaseResponse
{
    public string Message { get; init; } = message;
}