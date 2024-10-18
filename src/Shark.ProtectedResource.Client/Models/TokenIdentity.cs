namespace Shark.AuthorizationServer.Client.Models;

public sealed class TokenIdentity
{
    public string? UserId { get; set; }

    public string[]? Scopes { get; set; }
}