namespace Shark.AuthorizationServer.Sdk.Models;

public sealed class AuthorizationServerConfiguration
{
    public const string Name = nameof(AuthorizationServerConfiguration);

    public required string Address { get; set; }

    public required string ClientId { get; set; }

    public required string ClientSecret { get; set; }

    public required string ClientCallbackEndpoint { get; set; }
}