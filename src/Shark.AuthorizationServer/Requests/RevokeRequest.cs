using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public class RevokeRequest
{
    [DefaultValue("")]
    public required string token { get; set; }

    [DefaultValue("")]
    public string? token_hint { get; set; }
}