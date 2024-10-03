namespace Shark.AuthorizationServer.Requests;

public sealed class TokenRequest
{
    public string? grant_type { get; set; }

    public string? code { get; set; }

    public string? code_verifier { get; set; }

    public string? redirect_uri { get; set; }

    public string? client_id { get; set; }

    public string? client_secret { get; set; }

    public string? scope { get; set; }

    public string? refresh_token { get; set; }

    public string? username { get; set; }

    public string? password { get; set; }
}
