namespace Shark.AuthorizationServer.Responses;

public sealed class AuthorizeInternalTokenResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}