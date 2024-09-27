namespace Shark.AuthorizationServer.Models;

public record Client
{
    public required string ClientId { get; set; }

    public required string ClientName { get; set; }

    public required bool Enabled { get; set; }

    public required string ClientSecret { get; set; }

    public required string[] AllowedScopes { get; set; }

    public required string[] RedirectUris { get; set; }

    public required string Audience { get; set; }

    public required int AccessTokenLifetimeInSeconds { get; set; }

    public required int RefreshTokenLifetimeInSeconds { get; set; }
}