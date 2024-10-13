namespace Shark.AuthorizationServer.Core.Requests;

public sealed class IntrospectInternalRequest
{
    public required string Token { get; set; }
}