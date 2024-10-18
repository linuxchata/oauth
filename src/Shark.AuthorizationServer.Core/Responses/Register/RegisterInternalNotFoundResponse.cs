namespace Shark.AuthorizationServer.Core.Responses.Register;

public sealed class RegisterInternalBadRequestResponse(string message) : RegisterInternalBaseResponse
{
    public string Message { get; init; } = message;
}
