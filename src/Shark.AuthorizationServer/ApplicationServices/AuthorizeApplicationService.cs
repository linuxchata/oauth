using Shark.AuthorizationServer.Constants;
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
    IRedirectionService redirectionService,
    IHttpContextAccessor httpContextAccessor,
    ILogger<AuthorizeApplicationService> logger) : IAuthorizeApplicationService
{
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly ILogger<AuthorizeApplicationService> _logger = logger;

    public AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest request)
    {
        var response = ValidateRequest(request);
        if (response != null)
        {
            return response;
        }

        if (string.Equals(request.ResponseType, ResponseType.Code, StringComparison.OrdinalIgnoreCase))
        {
            var code = _stringGeneratorService.GenerateCode();

            StorePersistedGrant(request.ClientId, request.Scopes, code);

            var redirectUrl = _redirectionService.BuildClientCallbackUrl(
                request.RedirectUrl,
                code,
                request.Scopes,
                request.State);

            return new AuthorizeInternalResponse(redirectUrl);
        }

        _logger.LogWarning("Unsupported response type {responseType}", request.ResponseType);
        return new AuthorizeInternalBadRequestResponse(Error.InvalidResponseType);
    }

    private AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request)
    {
        var client = _clientRepository.GetById(request.ClientId);
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{clientId}]", request.ClientId);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        if (!client.RedirectUris.Contains(request.RedirectUrl))
        {
            _logger.LogWarning("Mismatched redirect URL [{redirectUrl}]", request.RedirectUrl);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        var allowedClientScopes = client.AllowedScopes.ToHashSet();
        var scopes = request.Scopes;
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope [{scope}] from request", scope);
                return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
            }
        }

        return null;
    }

    private void StorePersistedGrant(string clientId, string[]? scopes, string code)
    {
        var userName = _httpContextAccessor.HttpContext?.User.Identity?.Name;

        var persistedGrant = new PersistedGrant
        {
            Type = GrantType.AuthorizationCode,
            ClientId = clientId,
            Scopes = scopes,
            Value = code,
            UserName = userName,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };

        _persistedGrantStore.Add(persistedGrant);
    }
}