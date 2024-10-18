using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Client.Models;

public class ConfigurationResponse
{
    [JsonPropertyName("jwks_endpoint")]
    public required string JsonWebKeySetEndpoint { get; set; }
}