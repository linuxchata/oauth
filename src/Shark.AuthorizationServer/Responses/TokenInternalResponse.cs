namespace Shark.AuthorizationServer.Responses;

public sealed class TokenInternalResponse(string response) : TokenInternalBaseResponse
{
    public string Response { get; set; } = response;
}