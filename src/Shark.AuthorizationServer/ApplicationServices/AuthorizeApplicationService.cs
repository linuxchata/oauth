using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Abstractions.Repositories;
using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class AuthorizeApplicationService(
    IClientRepository clientRepository,
    IStringGeneratorService stringGeneratorService,
    IAccessTokenGeneratorService accessTokenGeneratorService,
    IPersistedGrantStore persistedGrantStore,
    IRedirectionService redirectionService,
    IHttpContextAccessor httpContextAccessor,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<AuthorizeApplicationService> logger) : IAuthorizeApplicationService
{
    private const int AuthorizationCodeExpirationInSeconds = 30;

    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IAccessTokenGeneratorService _accessTokenGeneratorService = accessTokenGeneratorService;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    private readonly IRedirectionService _redirectionService = redirectionService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<AuthorizeApplicationService> _logger = logger;

    public AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var client = _clientRepository.GetById(request.ClientId);

        var response = ValidateRequest(request, client);
        if (response != null)
        {
            return response;
        }

        if (IsResponseType(request.ResponseType, ResponseType.Code))
        {
            return HandleCodeResponseType(request);
        }
        else if (IsResponseType(request.ResponseType, ResponseType.Token))
        {
            return HandleTokenResponseType(request, client!);
        }

        return HandleUnsupportedResponseType(request.ResponseType);
    }

    private AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request, Client? client)
    {
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{clientId}]", request.ClientId);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        if (!client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URL [{redirectUri}]", request.RedirectUri);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        var allowedClientScopes = client.Scope.ToHashSet();
        var scopes = request.Scopes;
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope [{scope}] from request", scope);
                return new AuthorizeInternalBadRequestResponse(Error.InvalidScope);
            }
        }

        return null;
    }

    private bool IsResponseType(string responseType, string expectedResponseType)
    {
        return string.Equals(responseType, expectedResponseType, StringComparison.OrdinalIgnoreCase);
    }

    private AuthorizeInternalCodeResponse HandleCodeResponseType(AuthorizeInternalRequest request)
    {
        _logger.LogInformation(
            "Issuing authorization code for {responseType} response type",
            ResponseType.Code);

        var code = _stringGeneratorService.GenerateCode();

        StorePersistedGrant(request, code);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            code,
            request.Scopes,
            request.State);

        return new AuthorizeInternalCodeResponse(redirectUrl);
    }

    private AuthorizeInternalTokenResponse HandleTokenResponseType(AuthorizeInternalRequest request, Client client)
    {
        _logger.LogInformation(
            "Issuing access token for {responseType} response type",
            ResponseType.Token);

        var token = GenerateBearerToken(client!, request.Scopes);

        var redirectUrl = _redirectionService.BuildClientCallbackUrl(
            request.RedirectUri,
            token.AccessToken,
            token.TokenType);

        return new AuthorizeInternalTokenResponse(redirectUrl);
    }

    private AuthorizeInternalBadRequestResponse HandleUnsupportedResponseType(string responseType)
    {
        _logger.LogWarning("Unsupported response type {responseType}", responseType);
        return new AuthorizeInternalBadRequestResponse(Error.InvalidResponseType);
    }

    private void StorePersistedGrant(AuthorizeInternalRequest request, string code)
    {
        var userName = _httpContextAccessor.HttpContext?.User.Identity?.Name;

        var persistedGrant = new PersistedGrant
        {
            Type = GrantType.AuthorizationCode,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scopes,
            Value = code,
            UserName = userName,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            ExpiredIn = AuthorizationCodeExpirationInSeconds,
        };

        _persistedGrantStore.Add(persistedGrant);
    }

    private TokenResponse GenerateBearerToken(Client client, string[] scopes)
    {
        var userId = Guid.NewGuid().ToString();
        var accessToken = _accessTokenGeneratorService.Generate(userId, null, scopes, client.Audience);

        var token = new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = AccessTokenType.Bearer,
            ExpiresIn = _configuration.AccessTokenExpirationInSeconds,
        };

        return token;
    }
}