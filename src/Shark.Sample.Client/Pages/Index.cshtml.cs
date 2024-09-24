using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

namespace Shark.Sample.Client.Pages;

public class IndexModel : PageModel
{
    private readonly IWeatherForecastService _weatherForecastService;
    private readonly ISecurityService _securityService;
    private readonly IStateStore _stateStore;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public IndexModel(
        IWeatherForecastService weatherForecastService,
        ISecurityService securityService,
        IStateStore stateStore,
        IHttpContextAccessor httpContextAccessor)
    {
        _weatherForecastService = weatherForecastService;
        _securityService = securityService;
        _stateStore = stateStore;
        _httpContextAccessor = httpContextAccessor;
    }

    public List<WeatherForecast>? Data { get; private set; }

    public void OnGet()
    {
    }

    public void OnPostGetAuthToken()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(state);

        var redirectUrl = _securityService.BuildAuthorizeUrl(state);
        RedirectInternal(redirectUrl);
    }

    public async Task OnPostGetData()
    {
        Data = await _weatherForecastService.Get();
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}
