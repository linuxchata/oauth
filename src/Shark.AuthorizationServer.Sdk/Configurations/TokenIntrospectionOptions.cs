namespace Shark.AuthorizationServer.Sdk.Configurations;

public sealed class TokenIntrospectionOptions
{
    public bool Enabled { get; set; } = false;

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }
}