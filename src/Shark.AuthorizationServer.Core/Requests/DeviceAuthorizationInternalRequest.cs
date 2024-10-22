namespace Shark.AuthorizationServer.Core.Requests;

public sealed class DeviceAuthorizationInternalRequest
{
    public required string ClientId { get; set; }

    public required string ClientSecret { get; set; }

    public string? Scope { get; set; }
}