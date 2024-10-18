namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalResponse(string response) : TokenInternalBaseResponse
{
    public string Response { get; set; } = response;
}