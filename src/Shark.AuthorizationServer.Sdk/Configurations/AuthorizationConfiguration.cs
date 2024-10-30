namespace Shark.AuthorizationServer.Sdk.Configurations;

public sealed class AuthorizationConfiguration
{
    public const string Name = nameof(AuthorizationConfiguration);

    public required string AuthorizationServerUri { get; set; }

    public required string ClientId { get; set; }

    public required string ClientSecret { get; set; }

    public required string ClientCallbackEndpoint { get; set; }
}