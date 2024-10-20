using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.Configuration;

public sealed class ConfigurationJwksResponse
{
    [JsonPropertyName("e")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string? Exponent { get; set; } // The exponent part of the RSA key

    [JsonPropertyName("use")]
    public required string PublicKeyUse { get; set; }

    [JsonPropertyName("alg")]
    public required string Algorithm { get; set; }

    [JsonPropertyName("kty")]
    public required string KeyType { get; set; }

    [JsonPropertyName("kid")]
    public required string KeyId { get; set; }

    [JsonPropertyName("n")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string? Modulus { get; set; } // The modulus part of the RSA key

    [JsonPropertyName("k")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string? SymmetricKey { get; set; } // The Base64url-encoded symmetric key

    [JsonPropertyName("x5c")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public required string? X509CertificateChain { get; set; } // X.509 certificate chain
}