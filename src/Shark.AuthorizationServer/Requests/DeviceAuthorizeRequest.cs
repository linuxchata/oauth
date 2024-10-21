using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class DeviceAuthorizeRequest
{
    [DefaultValue("")]
    public required string client_id { get; set; }

    [DefaultValue("")]
    public string? scope { get; set; }
}