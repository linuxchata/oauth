using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Response;
using Shark.AuthorizationServer.Services;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class AuthorizeApplicationService : IAuthorizeApplicationService
{
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IClientRepository _clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore;

    public AuthorizeApplicationService(
        IClientRepository clientRepository,
        IStringGeneratorService stringGeneratorService,
        IPersistedGrantStore persistedGrantStore)
    {
        _clientRepository = clientRepository;
        _stringGeneratorService = stringGeneratorService;
        _persistedGrantStore = persistedGrantStore;
    }

    public AuthorizeInternalBaseResponse Execute(string clientId, string redirectUrl)
    {
        var client = _clientRepository.GetById(clientId);
        if (client is null || !client.RedirectUris.Contains(redirectUrl))
        {
            return new AuthorizeInternalBadRequestResponse("Invalid client");
        }

        var code = _stringGeneratorService.GenerateCode();
        var persistedGrant = new PersistedGrant
        {
            Type = AuthorizationCodeGrantType,
            ClientId = clientId,
            Value = code,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };
        _persistedGrantStore.Add(persistedGrant);

        return new AuthorizeInternalResponse(code);
    }
}