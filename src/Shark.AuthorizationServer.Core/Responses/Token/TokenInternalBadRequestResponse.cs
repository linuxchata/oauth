namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalBadRequestResponse(string error) : ITokenInternalResponse
{
    public ErrorResponseBody Error { get; init; } = new ErrorResponseBody(error);
}
