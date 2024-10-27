namespace Shark.AuthorizationServer.Domain;

public record PersistedGrant
{
    public required string Type { get; set; }

    public required string ClientId { get; set; }

    public string? RedirectUri { get; set; }

    public required string[] Scopes { get; set; }

    public string? AccessTokenId { get; set; }

    public required string Value { get; set; }

    public string? UserName { get; set; }

    public string? CodeChallenge { get; set; }

    public string? CodeChallengeMethod { get; set; }

    public required DateTime CreatedDate { get; set; }

    public int ExpiredIn { get; set; }
}