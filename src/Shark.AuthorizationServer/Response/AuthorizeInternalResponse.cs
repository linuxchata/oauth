namespace Shark.AuthorizationServer.Response;

public class AuthorizeInternalResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}