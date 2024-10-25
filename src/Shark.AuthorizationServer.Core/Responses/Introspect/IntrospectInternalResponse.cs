using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.Introspect;

public sealed class IntrospectInternalResponse : IIntrospectInternalResponse
{
    [JsonPropertyName("active")]
    public required bool Active { get; set; }

    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; set; }

    [JsonPropertyName("client_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientId { get; set; }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; set; }

    [JsonPropertyName("token_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenType { get; set; }

    [JsonPropertyName("exp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? Expire { get; set; }

    [JsonPropertyName("iat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? IssuedAt { get; set; }

    [JsonPropertyName("nbf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? NotBefore { get; set; }

    [JsonPropertyName("sub")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Subject { get; set; }

    [JsonPropertyName("aud")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Audience { get; set; }

    [JsonPropertyName("iss")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Issuer { get; set; }

    [JsonPropertyName("jti")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JwtId { get; set; }
}