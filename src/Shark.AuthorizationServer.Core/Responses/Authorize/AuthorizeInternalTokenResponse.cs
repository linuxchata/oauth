namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalTokenResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}