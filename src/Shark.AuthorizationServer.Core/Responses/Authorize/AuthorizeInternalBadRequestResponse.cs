namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalBadRequestResponse(string error) : IAuthorizeInternalResponse
{
    public ErrorResponseBody Error { get; init; } = new ErrorResponseBody(error);
}