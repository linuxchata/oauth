﻿using System.Text.Json.Serialization;

namespace Shark.ProtectedResource.Client.Models;

public sealed class ConfigurationJwksResponse
{
    [JsonPropertyName("e")]
    public required string Exponent { get; set; } // The exponent part of the RSA key

    [JsonPropertyName("use")]
    public required string PublicKeyUse { get; set; }

    [JsonPropertyName("alg")]
    public required string Algorithm { get; set; }

    [JsonPropertyName("kty")]
    public required string KeyType { get; set; }

    [JsonPropertyName("kid")]
    public required string KeyId { get; set; }

    [JsonPropertyName("n")]
    public required string Modulus { get; set; } // The modulus part of the RSA key
}