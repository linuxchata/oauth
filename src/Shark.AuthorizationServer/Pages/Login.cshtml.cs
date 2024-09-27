using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Helpers;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.Pages;

public class LoginModel(
    IClientRepository clientRepository,
    ILoginService loginService,
    IRedirectionService redirectionService) : PageModel
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly ILoginService _loginService = loginService;
    private readonly IRedirectionService _redirectionService = redirectionService;

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public string? UserName { get; set; }

    public void OnGet(string returnUrl)
    {
        ClientId = _redirectionService.GetClientId(returnUrl);

        var client = _clientRepository.GetById(ClientId);
        Scopes = client?.AllowedScopes.ToList() ?? [];
    }

    public async Task OnPost(string returnUrl, string userName, string[] selectedScopes)
    {
        await _loginService.SignIn(userName, selectedScopes);

        var authorizationServerUri = HttpContext.Request.GetUri();
        var authorizeUrl = _redirectionService.BuildAuthorizeUrl(authorizationServerUri, returnUrl, selectedScopes);
        HttpContext.Response.Redirect(authorizeUrl);
    }
}
