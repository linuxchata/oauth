namespace Shark.AuthorizationServer.Core.Responses;

public sealed class AuthorizeInternalCodeResponse(string redirectUrl) : AuthorizeInternalBaseResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}