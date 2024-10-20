using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.Configuration;

public sealed class ConfigurationResponse
{
    [JsonPropertyName("authorize_endpoint")]
    public required string AuthorizeEndpoint { get; set; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; set; }

    [JsonPropertyName("introspect_endpoint")]
    public required string IntrospectEndpoint { get; set; }

    [JsonPropertyName("revoke_endpoint")]
    public required string RevokeEndpoint { get; set; }

    [JsonPropertyName("register_endpoint")]
    public required string RegisterEndpoint { get; set; }

    [JsonPropertyName("userinfo_endpoint")]
    public required string UserInfoEndpoint { get; set; }

    [JsonPropertyName("jwks_endpoint")]
    public required string JsonWebKeySetEndpoint { get; set; }

    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; set; }

    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; set; }

    [JsonPropertyName("security_algorithm")]
    public required string[] SecurityAlgorithms { get; set; }
}