namespace Shark.AuthorizationServer.Core.Responses.Register;

public sealed class RegisterInternalBadRequestResponse(string message) : IRegisterInternalResponse
{
    public string Message { get; init; } = message;
}
