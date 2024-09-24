namespace Shark.AuthorizationServer.Requests;

public sealed class TokenInternalRequest
{
    public string ClientId { get; set; } = null!;

    public string ClientSecret { get; set; } = null!;

    public string GrantType { get; set; } = null!;

    public string? Code { get; set; }

    public string? RefreshToken { get; set; }

    public string RedirectUrl { get; set; } = null!;
}
