using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Pages;

public class LoginModel(
    IClientRepository clientRepository,
    IAuthorizeApplicationService authorizeApplicationService) : PageModel
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IAuthorizeApplicationService _authorizeApplicationService = authorizeApplicationService;

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public void OnGet(string clientId)
    {
        ClientId = clientId;

        var client = _clientRepository.GetById(ClientId);
        Scopes = client?.AllowedScopes.ToList() ?? [];
    }

    public void OnPost(string clientId, string[] selectedScopes, string state, string redirectBaseUrl)
    {
        var authorizeInternalRequest = new AuthorizeInternalRequest
        {
            ClientId = clientId,
            Scope = string.Join(' ', selectedScopes),
            State = state,
            RedirectUrl = redirectBaseUrl,
        };

        _authorizeApplicationService.Execute(authorizeInternalRequest);
    }
}
