using Shark.Sample.Client.Services;

namespace Shark.Sample.Client.ApplicationServices;

public sealed class CallBackApplicationService : ICallBackApplicationService
{
    private readonly ISecurityService _securityService;
    private readonly IStateStore _stateStore;
    private readonly ISecureTokenStore _securityStore;

    public CallBackApplicationService(
        ISecurityService securityService,
        IStateStore stateStore,
        ISecureTokenStore securityStore)
    {
        _securityService = securityService;
        _stateStore = stateStore;
        _securityStore = securityStore;
    }

    public async Task Execute(string code, string state)
    {
        var expectedState = _stateStore.Get();
        var secureToken = await _securityService.RequestAccessToken(code, state, expectedState);
        _securityStore.Add(secureToken);
    }
}