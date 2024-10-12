namespace Shark.AuthorizationServer.Requests;

public class RevokeInternalRequest
{
    public required string Token { get; set; }

    public string? TokenHint { get; set; }
}