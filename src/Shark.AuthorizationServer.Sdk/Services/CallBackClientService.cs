using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Abstractions.Stores;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public sealed class CallBackClientService(
    IAccessTokenClientInternalService clientAccessTokenService,
    IStateStore stateStore,
    ISecureTokenStore securityStore,
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    ILogger<CallBackClientService> logger) : ICallBackClientService
{
    private readonly IAccessTokenClientInternalService _clientAccessTokenService = clientAccessTokenService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly ISecureTokenStore _securityStore = securityStore;
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly ILogger<CallBackClientService> _logger = logger;

    public async Task Execute(string? accessToken, string? tokenType, string? code, string? scope, string? state)
    {
        if (IsImplicitGrantType(accessToken, tokenType))
        {
            HandleImplicitGrantType(accessToken);
        }
        else if (IsAuthorizationCodeGrantType(code))
        {
            await HandleAuthorizationCodeGrantType(code!, scope, state);
        }
    }

    private static bool IsImplicitGrantType(string? accessToken, string? tokenType)
    {
        return !string.IsNullOrWhiteSpace(accessToken) && !string.IsNullOrWhiteSpace(tokenType) &&
            string.Equals(tokenType, AccessTokenType.Bearer, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAuthorizationCodeGrantType(string? code)
    {
        return !string.IsNullOrWhiteSpace(code);
    }

    private void HandleImplicitGrantType(string? accessToken)
    {
        var secureToken = new SecureToken(accessToken, null, null);

        _securityStore.Add(GrantType.Implicit, secureToken);
    }

    private async Task HandleAuthorizationCodeGrantType(string code, string? scope, string? state)
    {
        var expectedState = _stateStore.Get(GrantType.AuthorizationCode);

        var proofKeyForCodeExchange = _proofKeyForCodeExchangeService.Get(expectedState);

        var secureToken = await _clientAccessTokenService.RequestForAuthorizationCodeFlow(
            code!,
            scope,
            state,
            expectedState,
            proofKeyForCodeExchange?.CodeVerifier);

        _logger.LogInformation("Access token is {AccessToken}", secureToken.AccessToken);
        _logger.LogInformation("ID token is {IdToken}", secureToken.IdToken);

        _securityStore.Add(GrantType.AuthorizationCode, secureToken);
    }
}