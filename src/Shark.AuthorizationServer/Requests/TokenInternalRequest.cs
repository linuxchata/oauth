namespace Shark.AuthorizationServer.Requests;

public sealed class TokenInternalRequest
{
    public string? GrantType { get; set; }

    public string? Code { get; set; }

    public string? CodeVerifier { get; set; }

    public string? RedirectUri { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string[] Scopes { get; set; } = null!;

    public string? RefreshToken { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }
}
