using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class AuthorizeApplicationService(
    IClientRepository clientRepository,
    IStringGeneratorService stringGeneratorService,
    IRedirectionService redirectionService,
    IHttpContextAccessor httpContextAccessor,
    IPersistedGrantStore persistedGrantStore) : IAuthorizeApplicationService
{
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;

    public void Execute(AuthorizeInternalRequest request)
    {
        var client = _clientRepository.GetById(request.ClientId);
        if (client is null || !client.RedirectUris.Contains(request.RedirectUrl))
        {
            throw new ArgumentException("Invalid client");
        }

        var allowedClientScopes = client.AllowedScopes.ToHashSet();
        var scopes = request.Scope?.Split(' ') ?? [];
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                throw new ArgumentException("Invalid client");
            }
        }

        var code = _stringGeneratorService.GenerateCode();
        var persistedGrant = new PersistedGrant
        {
            Type = AuthorizationCodeGrantType,
            ClientId = request.ClientId,
            Scope = request.Scope,
            Value = code,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };
        _persistedGrantStore.Add(persistedGrant);

        var redirectUrl = _redirectionService.BuildRedirectUrl(request.RedirectUrl, code, request.Scope, request.State);
        RedirectInternal(redirectUrl);
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}