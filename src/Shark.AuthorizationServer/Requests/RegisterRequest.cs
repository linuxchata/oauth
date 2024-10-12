using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class RegisterRequest
{
    public required string[] redirect_uris { get; set; }

    [DefaultValue("client_secret_basic")]
    public string? token_endpoint_auth_method { get; set; }

    [DefaultValue("authorization_code")]
    public required string grand_types { get; set; }

    [DefaultValue("code")]
    public required string response_types { get; set; }

    public required string client_name { get; set; }

    [DefaultValue("")]
    public string? client_uri { get; set; }

    [DefaultValue("")]
    public string? logo_uri { get; set; }

    public required string scope { get; set; }
}