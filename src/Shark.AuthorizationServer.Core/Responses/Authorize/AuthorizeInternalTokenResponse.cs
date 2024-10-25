namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalTokenResponse(string redirectUrl) : IAuthorizeInternalResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}