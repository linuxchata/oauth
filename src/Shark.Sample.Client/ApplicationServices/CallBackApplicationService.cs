﻿using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

namespace Shark.Sample.Client.ApplicationServices;

public sealed class CallBackApplicationService(
    IAuthorizationService authorizationService,
    IStateStore stateStore,
    ISecureTokenStore securityStore,
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    ILogger<AuthorizationService> logger) : ICallBackApplicationService
{
    private readonly IAuthorizationService _authorizationService = authorizationService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly ISecureTokenStore _securityStore = securityStore;
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly ILogger<AuthorizationService> _logger = logger;

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

        var secureToken = await _authorizationService.RequestAccessToken(
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