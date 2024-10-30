using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class WeatherForecastService(
    IHttpClientFactory httpClientFactory,
    IAccessTokenClientService clientAccessTokenCachedService,
    IOptions<ProtectedResourceConfiguration> options) : IWeatherForecastService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly IAccessTokenClientService _clientAccessTokenCachedService = clientAccessTokenCachedService;
    private readonly ProtectedResourceConfiguration _configuration = options.Value;

    public async Task<List<WeatherForecast>> Get(
        string grantType,
        string? username = null,
        string? password = null)
    {
        var header = await GetAuthenticationHeader(grantType, _configuration.Scope, username, password);
        return await GetInternal(header, grantType);
    }

    private async Task<List<WeatherForecast>> GetInternal(
        AuthenticationHeaderValue authorizationHeaderValue,
        string grantType)
    {
        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = authorizationHeaderValue;
            var response = await httpClient.GetAsync(_configuration.Endpoint);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<List<WeatherForecast>>(content);

            return result ?? [];
        }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.Unauthorized)
        {
            _clientAccessTokenCachedService.Invalidate(grantType);
            throw;
        }
    }

    private async Task<AuthenticationHeaderValue> GetAuthenticationHeader(
        string grantType,
        string? scope = null,
        string? username = null,
        string? password = null)
    {
        var accessToken = await _clientAccessTokenCachedService.Get(grantType, scope, username, password);
        return new AuthenticationHeaderValue(AccessTokenType.Bearer, accessToken);
    }
}