namespace Shark.AuthorizationServer.Services;

public sealed class LoginService(
    IRedirectionService redirectionService,
    IHttpContextAccessor httpContextAccessor) : ILoginService
{
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public void PostLogin(string redirectBaseUrl, string code, string[] selectedScopes, string state)
    {
        if (!string.IsNullOrEmpty(redirectBaseUrl))
        {
            // TODO: Update persistent grand store
            var scope = string.Join(' ', selectedScopes);
            var redirectUrl = _redirectionService.BuildRedirectUrl(redirectBaseUrl, code, scope, state);
            RedirectInternal(redirectUrl);
        }
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}