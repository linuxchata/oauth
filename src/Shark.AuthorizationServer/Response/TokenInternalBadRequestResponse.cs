namespace Shark.AuthorizationServer.Response;

public sealed class TokenInternalBadRequestResponse : TokenInternalBaseResponse
{
    public TokenInternalBadRequestResponse(string message)
    {
        Message = message;
    }

    public string Message { get; init; }
}
