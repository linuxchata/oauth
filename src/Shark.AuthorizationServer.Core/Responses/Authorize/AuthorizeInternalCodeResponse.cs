namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalCodeResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}