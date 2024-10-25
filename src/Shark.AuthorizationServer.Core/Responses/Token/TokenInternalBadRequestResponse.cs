namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalBadRequestResponse(string message) : ITokenInternalResponse
{
    public string Message { get; init; } = message;
}
