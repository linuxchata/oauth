namespace Shark.AuthorizationServer.Models;

public record class PersistedGrant
{
    public required string Type { get; set; }

    public required string ClientId { get; set; }

    public string[]? Scopes { get; set; }

    public required string Value { get; set; }

    public string? UserName { get; set; }

    public int ExpiredIn { get; set; }
}