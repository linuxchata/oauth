using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.Pages;

public class LoginModel : PageModel
{
    private readonly IClientRepository _clientRepository;
    private readonly ILoginService _loginService;

    public LoginModel(
        IClientRepository clientRepository,
        ILoginService loginService)
    {
        _clientRepository = clientRepository;
        _loginService = loginService;
    }

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public void OnGet(string clientId)
    {
        ClientId = clientId;

        var client = _clientRepository.GetById(ClientId);
        Scopes = client?.AllowedScopes.ToList() ?? [];
    }

    public void OnPost(string redirectBaseUrl, string code, string[] selectedScopes, string state)
    {
        _loginService.PostLogin(redirectBaseUrl, code, selectedScopes, state);
    }
}
