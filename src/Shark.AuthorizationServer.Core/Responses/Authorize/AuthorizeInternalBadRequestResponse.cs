namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalBadRequestResponse(string message) : AuthorizeInternalBaseResponse
{
    public string Message { get; init; } = message;
}