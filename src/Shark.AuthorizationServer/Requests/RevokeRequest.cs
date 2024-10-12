namespace Shark.AuthorizationServer.Requests;

public class RevokeRequest
{
    public required string token { get; set; }

    public string? token_hint { get; set; }
}