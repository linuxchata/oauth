using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class AuthorizeApplicationService(
    IClientRepository clientRepository,
    IStringGeneratorService stringGeneratorService,
    IPersistedGrantStore persistedGrantStore,
    IRedirectionService redirectionService) : IAuthorizeApplicationService
{
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    private readonly IRedirectionService _redirectionService = redirectionService;

    public AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest request)
    {
        var response = ValidateRequest(request);
        if (response != null)
        {
            return response;
        }

        var code = _stringGeneratorService.GenerateCode();

        StorePersistedGrant(request.ClientId, request.Scopes, code);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUrl,
            code,
            request.Scopes,
            request.State);

        return new AuthorizeInternalResponse(redirectUrl);
    }

    private AuthorizeInternalBaseResponse? ValidateRequest(AuthorizeInternalRequest request)
    {
        var client = _clientRepository.GetById(request.ClientId);
        if (client is null || !client.RedirectUris.Contains(request.RedirectUrl))
        {
            return new AuthorizeInternalBadRequestResponse("Invalid client");
        }

        var allowedClientScopes = client.AllowedScopes.ToHashSet();
        var scopes = request.Scopes;
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                return new AuthorizeInternalBadRequestResponse("Invalid client");
            }
        }

        return null;
    }

    private void StorePersistedGrant(string clientId, string[] scopes, string code)
    {
        var persistedGrant = new PersistedGrant
        {
            Type = AuthorizationCodeGrantType,
            ClientId = clientId,
            Scopes = scopes,
            Value = code,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };

        _persistedGrantStore.Add(persistedGrant);
    }
}