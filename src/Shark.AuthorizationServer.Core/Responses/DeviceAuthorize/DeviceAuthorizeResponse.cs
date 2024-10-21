using System.Text.Json.Serialization;

namespace Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;

public sealed class DeviceAuthorizeResponse : DeviceAuthorizeBaseResponse
{
    [JsonPropertyName("device_code")]
    public required string DeviceCode { get; set; }

    [JsonPropertyName("user_code")]
    public required string UserCode { get; set; }
}
