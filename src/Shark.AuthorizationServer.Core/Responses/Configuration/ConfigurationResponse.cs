using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.Configuration;

public sealed class ConfigurationResponse
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    [JsonPropertyName("jwks_uri")]
    public required string JsonWebKeySetEndpoint { get; set; }

    [JsonPropertyName("authorize_endpoint")]
    public required string AuthorizeEndpoint { get; set; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; set; }

    [JsonPropertyName("introspect_endpoint")]
    public required string IntrospectEndpoint { get; set; }

    [JsonPropertyName("revoke_endpoint")]
    public required string RevokeEndpoint { get; set; }

    [JsonPropertyName("registration_endpoint")]
    public required string RegistrationEndpoint { get; set; }

    [JsonPropertyName("userinfo_endpoint")]
    public required string UserInfoEndpoint { get; set; }

    [JsonPropertyName("device_authorization_endpoint")]
    public required string DeviceAuthorizationEndpoint { get; set; }

    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; set; }

    [JsonPropertyName("response_types_supported")]
    public required string[] ResponseTypesSupported { get; set; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; set; }

    [JsonPropertyName("security_algorithm")]
    public required string[] SecurityAlgorithms { get; set; }
}