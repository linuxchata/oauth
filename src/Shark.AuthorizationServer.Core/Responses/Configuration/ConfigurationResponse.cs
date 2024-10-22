using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.Configuration;

public sealed class ConfigurationResponse
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    [JsonPropertyName("jwks_uri")]
    public required string JsonWebKeySetEndpoint { get; set; }

    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; set; }

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

    [JsonPropertyName("scopes_supported")]
    public required string[] ScopesSupported { get; set; }

    [JsonPropertyName("claims_supported")]
    public required string[] ClaimsSupported { get; set; }

    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; set; }

    [JsonPropertyName("response_types_supported")]
    public required string[] ResponseTypesSupported { get; set; }

    [JsonPropertyName("subject_types_supported")]
    public required string[] SubjectTypesSupported { get; set; }

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required string[] TokenEndpointAuthMethodsSupported { get; set; }

    [JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")]
    public required string[] TokenEndpointAuthSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required string[] IdTokenSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; set; }
}