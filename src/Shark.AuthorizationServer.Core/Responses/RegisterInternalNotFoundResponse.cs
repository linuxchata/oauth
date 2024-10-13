namespace Shark.AuthorizationServer.Core.Responses;

public sealed class RegisterInternalBadRequestResponse(string message) : RegisterInternalBaseResponse
{
    public string Message { get; init; } = message;
}
