using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class RegisterUpdateRequest
{
    public required string[] redirect_uris { get; set; }

    public required string token_endpoint_auth_method { get; set; }

    [DefaultValue("authorization_code")]
    public required string grant_types { get; set; }

    [DefaultValue("code")]
    public required string response_types { get; set; }

    public required string client_name { get; set; }

    public required string client_id { get; set; }

    public string? client_secret { get; set; }

    [DefaultValue("")]
    public string? client_uri { get; set; }

    [DefaultValue("")]
    public string? logo_uri { get; set; }

    public required string scope { get; set; }

    [DefaultValue("")]
    public required string audience { get; set; }
}