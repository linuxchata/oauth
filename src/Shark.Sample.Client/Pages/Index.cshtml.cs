using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Pages;

public class IndexModel(
    IWeatherForecastService weatherForecastService,
    IAuthorizationService authorizationService,
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    IStateStore stateStore,
    IHttpContextAccessor httpContextAccessor) : PageModel
{
    private readonly IWeatherForecastService _weatherForecastService = weatherForecastService;
    private readonly IAuthorizationService _authorizationService = authorizationService;
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public List<WeatherForecast>? Data { get; private set; }

    public void OnPostGetAuthTokenAuthorizationCode()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(GrantType.AuthorizationCode, state);

        var loginPageUrl = _authorizationService.BuildLoginPageUrl(Security.CodeResponseType, state);

        RedirectInternal(loginPageUrl);
    }

    public async Task OnPostGetDataAuthorizationCode()
    {
        Data = await _weatherForecastService.Get(GrantType.AuthorizationCode);
    }

    public void OnPostGetAuthTokenAuthorizationCodePkce()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(GrantType.AuthorizationCode, state);

        var pkce = _proofKeyForCodeExchangeService.Generate(state);

        var loginPageUrl = _authorizationService.BuildLoginPageUrl(Security.CodeResponseType, state, pkce);

        RedirectInternal(loginPageUrl);
    }

    public async Task OnPostGetDataAuthorizationCodePkce()
    {
        Data = await _weatherForecastService.Get(GrantType.AuthorizationCode);
    }

    public void OnPostGetAuthTokenImplicit()
    {
        var loginPageUrl = _authorizationService.BuildLoginPageUrl(Security.TokenResponseType, null);

        RedirectInternal(loginPageUrl);
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

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}
