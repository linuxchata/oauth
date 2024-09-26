using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Repositories;

namespace Shark.AuthorizationServer.Pages;

public class LoginModel(
    IClientRepository clientRepository,
    IAuthorizeApplicationService authorizeApplicationService) : PageModel
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IAuthorizeApplicationService _authorizeApplicationService = authorizeApplicationService;

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public string? UserName { get; set; }

    public void OnGet(string clientId)
    {
        ClientId = clientId;

        var client = _clientRepository.GetById(ClientId);
        Scopes = client?.AllowedScopes.ToList() ?? [];
    }

    public void OnPost(string clientId, string userName, string[] selectedScopes, string state, string redirectBaseUrl)
    {
        // Create authentication session
    }
}
