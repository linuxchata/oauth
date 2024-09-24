namespace Shark.AuthorizationServer.Response;

public sealed class AuthorizeInternalBadRequestResponse : AuthorizeInternalBaseResponse
{
    public AuthorizeInternalBadRequestResponse(string message)
    {
        Message = message;
    }

    public string Message { get; init; }
}
