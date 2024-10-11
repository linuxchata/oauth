using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Requests;

public sealed class IntrospectRequest
{
    [JsonPropertyName("token")]
    public required string Token { get; set; }
}