using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class DeviceAuthorizationRequest
{
    [DefaultValue("")]
    public required string client_id { get; set; }

    [DefaultValue("")]
    public required string client_secret { get; set; }

    [DefaultValue("")]
    public string? scope { get; set; }
}