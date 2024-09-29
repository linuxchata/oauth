using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

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
        if (!string.IsNullOrWhiteSpace(accessToken) && !string.IsNullOrWhiteSpace(tokenType))
        {
            var secureToken = new SecureToken(accessToken, null);
            _securityStore.Add(secureToken);
        }
        else if (!string.IsNullOrWhiteSpace(code))
        {
            var expectedState = _stateStore.Get();

            var secureToken = await _authorizationService.RequestAccessToken(code, scope, state, expectedState);

            _securityStore.Add(secureToken);
        }
    }
}