namespace Shark.AuthorizationServer.Requests;

public sealed class AuthorizeInternalRequest
{
    public required string ResponseType { get; set; }

    public required string ClientId { get; set; }

    public required string[] Scopes { get; set; }

    public string? State { get; set; }

    public required string RedirectUrl { get; set; }
}