namespace Shark.AuthorizationServer.Requests;

public sealed class AuthorizeInternalRequest
{
    public string ClientId { get; set; } = null!;

    public string Scope { get; set; } = null!;

    public string State { get; set; } = null!;

    public string RedirectUrl { get; set; } = null!;
}