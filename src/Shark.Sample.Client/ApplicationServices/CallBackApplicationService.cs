using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.ApplicationServices;

public sealed class CallBackApplicationService(
    IAuthorizationService authorizationService,
    IStateStore stateStore,
    ISecureTokenStore securityStore) : ICallBackApplicationService
{
    private readonly IAuthorizationService _authorizationService = authorizationService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly ISecureTokenStore _securityStore = securityStore;

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

    private bool IsImplicitGrantType(string? accessToken, string? tokenType)
    {
        return !string.IsNullOrWhiteSpace(accessToken) && !string.IsNullOrWhiteSpace(tokenType) &&
            string.Equals(tokenType, AccessTokenType.Bearer, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsAuthorizationCodeGrantType(string? code)
    {
        return !string.IsNullOrWhiteSpace(code);
    }

    private void HandleImplicitGrantType(string? accessToken)
    {
        var secureToken = new SecureToken(accessToken, null);

        _securityStore.Add(GrantType.Implicit, secureToken);
    }

    private async Task HandleAuthorizationCodeGrantType(string code, string? scope, string? state)
    {
        var expectedState = _stateStore.Get(GrantType.AuthorizationCode);

        var secureToken = await _authorizationService.RequestAccessToken(code!, scope, state, expectedState);

        _securityStore.Add(GrantType.AuthorizationCode, secureToken);
    }
}