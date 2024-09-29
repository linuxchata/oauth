namespace Shark.AuthorizationServer.Requests;

public sealed class TokenRequest
{
    public string client_id { get; set; } = null!;

    public string client_secret { get; set; } = null!;

    public string grant_type { get; set; } = null!;

    public string? scope { get; set; } = null!;

    public string? code { get; set; }

    public string? refresh_token { get; set; }

    public string? redirect_url { get; set; } = null!;
}
