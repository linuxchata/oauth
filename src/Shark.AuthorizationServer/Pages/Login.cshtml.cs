using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.Pages;

public class LoginModel : PageModel
{
    private readonly IClientRepository _clientRepository;
    private readonly IRedirectionService _redirectionService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(
        IClientRepository clientRepository,
        IRedirectionService redirectionService,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LoginModel> logger)
    {
        _clientRepository = clientRepository;
        _redirectionService = redirectionService;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public string? ClientId { get; private set; }

    public List<string>? Scopes { get; private set; }

    public void OnGet(string clientId)
    {
        ClientId = clientId;

        var client = _clientRepository.GetById(ClientId);
        Scopes = client?.AllowedScopes.ToList() ?? [];
    }

    public void OnPost(string code, string[] selectedScopes, string redirectBaseUrl, string state)
    {
        if (!string.IsNullOrEmpty(redirectBaseUrl))
        {
            var redirectUrl = _redirectionService.BuildRedirectUrl(redirectBaseUrl, code, state);
            RedirectInternal(redirectUrl);
        }
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}
