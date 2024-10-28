using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Pages;

public class IndexModel(
    IClientAuthorizationService clientAuthorizationService,
    IWeatherForecastService weatherForecastService,
    IAuthorizationService authorizationService,
    Abstractions.Services.IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    IStateStore stateStore,
    IHttpContextAccessor httpContextAccessor) : PageModel
{
    private readonly IClientAuthorizationService _clientAuthorizationService = clientAuthorizationService;
    private readonly IWeatherForecastService _weatherForecastService = weatherForecastService;
    private readonly IAuthorizationService _authorizationService = authorizationService;
    private readonly Abstractions.Services.IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public List<WeatherForecast>? Data { get; private set; }

    public void OnPostGetAuthTokenAuthorizationCode()
    {
        _clientAuthorizationService.LoginAuthorizationCodeFlow();
    }

    public async Task OnPostGetDataAuthorizationCode()
    {
        Data = await _weatherForecastService.Get(GrantType.AuthorizationCode);
    }

    public void OnPostGetAuthTokenAuthorizationCodePkce()
    {
        _clientAuthorizationService.LoginAuthorizationCodeFlowWithPkce();
    }

    public async Task OnPostGetDataAuthorizationCodePkce()
    {
        Data = await _weatherForecastService.Get(GrantType.AuthorizationCode);
    }

    public void OnPostGetAuthTokenImplicit()
    {
        _clientAuthorizationService.LoginImplicitFlow();
    }

    public async Task OnPostGetDataImplicit()
    {
        Data = await _weatherForecastService.Get(GrantType.Implicit);
    }

    public async Task OnPostGetDataResourceOwnerCredentials()
    {
        Data = await _weatherForecastService.Get(GrantType.ResourceOwnerCredentials);
    }

    public async Task OnPostGetDataClientCredentials()
    {
        Data = await _weatherForecastService.Get(GrantType.ClientCredentials);
    }
}
