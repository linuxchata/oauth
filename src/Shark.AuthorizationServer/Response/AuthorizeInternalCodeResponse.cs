namespace Shark.AuthorizationServer.Response;

public sealed class AuthorizeInternalCodeResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}