using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Sdk.Models;

public sealed class ConfigurationResponse
{
    [JsonPropertyName("jwks_uri")]
    public required string JsonWebKeySetEndpoint { get; set; }
}