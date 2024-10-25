namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalBadRequestResponse(string message) : IAuthorizeInternalResponse
{
    public string Message { get; init; } = message;
}