namespace Shark.AuthorizationServer.Requests;

public sealed class IntrospectInternalRequest
{
    public required string Token { get; set; }
}