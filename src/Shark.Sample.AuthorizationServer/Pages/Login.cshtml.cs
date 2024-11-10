using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Extensions;

namespace Shark.Sample.AuthorizationServer.Pages;

public sealed class LoginModel(
    IClientRepository clientRepository,
    IRedirectionService redirectionService) : PageModel
{
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IRedirectionService _redirectionService = redirectionService;

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public string? UserName { get; set; } = "Alice";

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return RedirectToPage("Error");
        }

        ClientId = _redirectionService.GetClientId(returnUrl);

        var client = await _clientRepository.Get(ClientId);
        if (client == null)
        {
            return RedirectToPage("Error");
        }

        Scopes = client.Scope?.ToList() ?? [];

        return Page();
    }

    public async Task OnPost(string returnUrl, string userName, string[] selectedScopes)
    {
        await HttpContext.SignInAsync(userName, selectedScopes, Amr.Pwd);

        var authorizeEndpointUrl = _redirectionService.BuildAuthorizeUrl(returnUrl, selectedScopes);

        HttpContext.Response.Redirect(authorizeEndpointUrl);
    }
}
