using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

namespace Shark.Sample.Client.Pages;

public class IndexModel(
    IWeatherForecastService weatherForecastService,
    IAuthorizationService authorizationService,
    IStateStore stateStore,
    IHttpContextAccessor httpContextAccessor) : PageModel
{
    private readonly IWeatherForecastService _weatherForecastService = weatherForecastService;
    private readonly IAuthorizationService _authorizationService = authorizationService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public List<WeatherForecast>? Data { get; private set; }

    public void OnGet()
    {
    }

    public void OnPostGetAuthToken()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(state);

        var loginPageUrl = _authorizationService.BuildLoginPageUrl(Security.CodeResponseType, state);

        RedirectInternal(loginPageUrl);
    }

    public void OnPostGetAuthTokenWithImplicit()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(state);

        var loginPageUrl = _authorizationService.BuildLoginPageUrl(Security.TokenResponseType, state);

        RedirectInternal(loginPageUrl);
    }

    public async Task OnPostGetDataWithResourceOwnerCredentials()
    {
        Data = await _weatherForecastService.GetWithResourceOwnerCredentials();
    }

    public async Task OnPostGetData()
    {
        Data = await _weatherForecastService.Get();
    }

    public async Task OnPostGetDataWithClientCredentials()
    {
        Data = await _weatherForecastService.GetWithClientCredentials();
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}
