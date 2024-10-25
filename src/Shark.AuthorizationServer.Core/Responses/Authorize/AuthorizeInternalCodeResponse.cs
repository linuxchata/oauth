namespace Shark.AuthorizationServer.Core.Responses.Authorize;

public sealed class AuthorizeInternalCodeResponse(string redirectUrl) : IAuthorizeInternalResponse
{
    public string RedirectUrl { get; init; } = redirectUrl;
}