using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class IntrospectRequest
{
    [DefaultValue("")]
    public required string token { get; set; }
}