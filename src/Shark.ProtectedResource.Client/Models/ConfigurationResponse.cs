using System.Text.Json.Serialization;

namespace Shark.ProtectedResource.Client.Models;

public class ConfigurationResponse
{
    [JsonPropertyName("jwks_endpoint")]
    public required string JsonWebKeySetEndpoint { get; set; }
}