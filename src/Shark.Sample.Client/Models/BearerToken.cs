using Newtonsoft.Json;

namespace Shark.Sample.Client.Models;

public sealed class BearerToken
{
    [JsonProperty(PropertyName = "access_token")]
    public string AccessToken { get; set; } = null!;

    [JsonProperty(PropertyName = "refresh_token")]
    public string RefreshToken { get; set; } = null!;

    [JsonProperty(PropertyName = "token_type")]
    public string TokenType { get; set; } = null!;

    [JsonProperty(PropertyName = "expires_in")]
    public int ExpiresIn { get; set; }
}