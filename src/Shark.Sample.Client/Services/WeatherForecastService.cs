using System.Net;
using Newtonsoft.Json;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class WeatherForecastService : IWeatherForecastService
{
    private const string Endpoint = "http://localhost:9002/weatherforecast";
    private const string AuthorizationHeaderName = "Authorization";

    private readonly ISecureTokenStore _securityStore;
    private readonly ISecurityService _securityService;
    private readonly IHttpClientFactory _httpClientFactory;

    public WeatherForecastService(
        ISecureTokenStore securityStore,
        ISecurityService securityService,
        IHttpClientFactory httpClientFactory)
    {
        _securityStore = securityStore;
        _securityService = securityService;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<List<WeatherForecast>> Get()
    {
        var accessToken = await GetAccessToken();

        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Add(AuthorizationHeaderName, $"Bearer {accessToken}");
            var response = await httpClient.GetAsync(Endpoint);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonConvert.DeserializeObject<List<WeatherForecast>>(content);

            return result ?? [];
        }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.Unauthorized)
        {
            _securityStore.RemoveAccessToken();
            throw;
        }
        catch (HttpRequestException)
        {
            throw;
        }
    }

    private async Task<string> GetAccessToken()
    {
        var accessToken = _securityStore.GetAccessToken();
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var refreshToken = _securityStore.GetRefreshToken();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new ArgumentException("Missing access token and refresh token");
        }

        var secureToken = await _securityService.RequestAccessToken(refreshToken!);
        _securityStore.Add(secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException("Missing access token");
    }
}