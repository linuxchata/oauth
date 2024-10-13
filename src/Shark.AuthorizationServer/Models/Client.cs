namespace Shark.AuthorizationServer.Models;

public record Client
{
    public required string ClientName { get; set; }

    public required bool Enabled { get; set; }

    public required string ClientId { get; set; }

    public required string ClientSecret { get; set; }

    public required long ClientIdIssuedAt { get; set; }

    public required long ClientSecretExpiresAt { get; set; }

    public required string[] RedirectUris { get; set; }

    public required string[] GrantTypes { get; set; }

    public required string[] ResponseTypes { get; set; }

    public required string TokenEndpointAuthMethod { get; set; }

    public string? ClientUri { get; set; }

    public string? LogoUri { get; set; }

    public required string[] Scope { get; set; }

    public required string Audience { get; set; }

    public required int AccessTokenLifetimeInSeconds { get; set; }

    public required int RefreshTokenLifetimeInSeconds { get; set; }
}