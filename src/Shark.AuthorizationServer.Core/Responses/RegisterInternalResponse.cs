using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses;

public sealed class RegisterInternalResponse : RegisterInternalBaseResponse
{
    [JsonPropertyName("client_name")]
    public required string ClientName { get; set; }

    [JsonPropertyName("client_id")]
    public required string ClientId { get; set; }

    [JsonPropertyName("client_secret")]
    public required string ClientSecret { get; set; }

    [JsonPropertyName("client_id_issued_at")]
    public required long ClientIdIssuedAt { get; set; }

    [JsonPropertyName("client_secret_expires_at")]
    public required long ClientSecretExpiresAt { get; set; }

    [JsonPropertyName("redirect_uris")]
    public required string[] RedirectUris { get; set; }

    [JsonPropertyName("grant_types")]
    public required string[] GrantTypes { get; set; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public required string TokenEndpointAuthMethod { get; set; }

    [JsonPropertyName("registration_access_token")]
    public required string RegistrationAccessToken { get; set; }

    [JsonPropertyName("registration_client_uri")]
    public required string RegistrationClientUri { get; set; }
}