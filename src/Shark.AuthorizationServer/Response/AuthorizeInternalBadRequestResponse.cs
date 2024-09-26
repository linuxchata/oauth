namespace Shark.AuthorizationServer.Response;

public sealed class AuthorizeInternalBadRequestResponse(string message) : AuthorizeInternalBaseResponse
{
    public string Message { get; init; } = message;
}