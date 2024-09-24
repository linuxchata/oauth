namespace Shark.AuthorizationServer.Response;

public class AuthorizeInternalResponse : AuthorizeInternalBaseResponse
{
    public AuthorizeInternalResponse(string code)
    {
        Code = code;
    }

    public string Code { get; init; }
}