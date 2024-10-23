using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class TokenRequest
{
    [DefaultValue("")]
    public string? grant_type { get; set; }

    [DefaultValue("")]
    public string? code { get; set; }

    [DefaultValue("")]
    public string? code_verifier { get; set; }

    [DefaultValue("")]
    public string? redirect_uri { get; set; }

    [DefaultValue("")]
    public string? client_id { get; set; }

    [DefaultValue("")]
    public string? client_secret { get; set; }

    [DefaultValue("")]
    public string? scope { get; set; }

    [DefaultValue("")]
    public string? refresh_token { get; set; }

    [DefaultValue("")]
    public string? username { get; set; }

    [DefaultValue("")]
    public string? password { get; set; }

    [DefaultValue("")]
    public string? device_code { get; set; }
}
