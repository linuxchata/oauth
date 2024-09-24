namespace Shark.AuthorizationServer.Response;

public sealed class TokenInternalResponse : TokenInternalBaseResponse
{
    public TokenInternalResponse(string response)
    {
        Response = response;
    }

    public string Response { get; set; }
}