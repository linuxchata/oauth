namespace Shark.AuthorizationServer.Core.Responses;

public sealed class ErrorResponseBody(string error)
{
    public string Error { get; init; } = error;
}