namespace Shark.AuthorizationServer.Core.Requests;

public sealed class DeviceAuthorizeInternalRequest
{
    public required string ClientId { get; set; }

    public string? Scope { get; set; }
}