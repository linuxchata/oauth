namespace Shark.AuthorizationServer.Core.Requests;

public sealed class DeviceAuthorizationInternalRequest
{
    public required string ClientId { get; set; }

    public required string ClientSecret { get; set; }

    public required string[] Scopes { get; set; }
}