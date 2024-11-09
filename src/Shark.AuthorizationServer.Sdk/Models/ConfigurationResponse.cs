using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Sdk.Models;

public sealed class IntrospectResponse
{
    [JsonPropertyName("active")]
    public required bool Active { get; set; }
}