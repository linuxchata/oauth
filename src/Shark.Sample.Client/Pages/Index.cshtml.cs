using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Pages;

public class IndexModel(
    IClientAuthorizationService clientAuthorizationService,
    IWeatherForecastService weatherForecastService) : PageModel
{
    private readonly IClientAuthorizationService _clientAuthorizationService = clientAuthorizationService;
    private readonly IWeatherForecastService _weatherForecastService = weatherForecastService;

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
        Data = await _weatherForecastService.Get(GrantType.ResourceOwnerCredentials, "alice", "secret");
    }

    public async Task OnPostGetDataClientCredentials()
    {
        Data = await _weatherForecastService.Get(GrantType.ClientCredentials);
    }
}
