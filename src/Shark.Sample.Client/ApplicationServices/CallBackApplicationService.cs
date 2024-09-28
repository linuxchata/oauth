using Shark.Sample.Client.Services;

namespace Shark.Sample.Client.ApplicationServices;

public sealed class CallBackApplicationService(
    IAuthorizationService securityService,
    IStateStore stateStore,
    ISecureTokenStore securityStore) : ICallBackApplicationService
{
    private readonly IAuthorizationService _securityService = securityService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly ISecureTokenStore _securityStore = securityStore;

    public async Task Execute(string code, string? scope, string? state)
    {
        var expectedState = _stateStore.Get();

        var secureToken = await _securityService.RequestAccessToken(code, scope, state, expectedState);

        _securityStore.Add(secureToken);
    }
}