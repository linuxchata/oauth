namespace Shark.AuthorizationServer.Responses;

public sealed class IntrospectInternalResponse : IntrospectInternalBaseResponse
{
    public bool Active { get; set; }
}