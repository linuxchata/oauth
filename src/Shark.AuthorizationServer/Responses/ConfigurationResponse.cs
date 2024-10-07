using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Responses;

public sealed class ConfigurationResponse
{
    [JsonPropertyName("authorize_endpoint")]
    public required string AuthorizeEndpoint { get; set; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; set; }

    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; set; }

    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; set; }

    [JsonPropertyName("security_algorithm")]
    public required string[] SecurityAlgorithms { get; set; }
}