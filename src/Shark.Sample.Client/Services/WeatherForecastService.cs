using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class WeatherForecastService(
    IHttpClientFactory httpClientFactory,
    ISecureTokenStore secureTokenStore,
    IAuthorizationService authorizationService) : IWeatherForecastService
{
    private const string ProtectedResourceEndpoint = "https://localhost:9002/weatherforecast";
    private const string MissingAccessTokenErrorMessage = "Missing access token";

    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly ISecureTokenStore _secureTokenStore = secureTokenStore;
    private readonly IAuthorizationService _authorizationService = authorizationService;

    public async Task<List<WeatherForecast>> Get(string grantType)
    {
        if (string.Equals(grantType, GrantType.AuthorizationCode, StringComparison.OrdinalIgnoreCase))
        {
            var header = await GetHeaderForAuthorizationCode(grantType);
            return await GetInternal(header, grantType);
        }
        if (string.Equals(grantType, GrantType.Implicit, StringComparison.OrdinalIgnoreCase))
        {
            var header = GetHeaderForImplicit(grantType);
            return await GetInternal(header, grantType);
        }
        else if (string.Equals(grantType, GrantType.ClientCredentials, StringComparison.OrdinalIgnoreCase))
        {
            var header = await GetHeaderForClientCredentials("read", grantType);
            return await GetInternal(header, grantType);
        }
        else if (string.Equals(grantType, GrantType.ResourceOwnerCredentials, StringComparison.OrdinalIgnoreCase))
        {
            var header = await GetHeaderForResourceOwnerCredentials("alice", "secret", "read", grantType);
            return await GetInternal(header, grantType);
        }

        throw new ArgumentException("Unsupported grant type");
    }

    private async Task<List<WeatherForecast>> GetInternal(
        AuthenticationHeaderValue authorizationHeaderValue,
        string grantType)
    {
        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = authorizationHeaderValue;
            var response = await httpClient.GetAsync(ProtectedResourceEndpoint);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<List<WeatherForecast>>(content);

            return result ?? [];
        }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.Unauthorized)
        {
            _secureTokenStore.RemoveAccessToken(grantType);
            throw;
        }
    }

    private async Task<AuthenticationHeaderValue> GetHeaderForAuthorizationCode(string grantType)
    {
        var accessToken = await GetAccessTokenAuthorizationCode(grantType);
        return new AuthenticationHeaderValue(AccessTokenType.Bearer, accessToken);
    }

    private AuthenticationHeaderValue GetHeaderForImplicit(string grantType)
    {
        var accessToken = GetAccessTokenImplicit(grantType);
        return new AuthenticationHeaderValue(AccessTokenType.Bearer, accessToken);
    }

    private async Task<AuthenticationHeaderValue> GetHeaderForClientCredentials(string? scope, string grantType)
    {
        var accessToken = await GetAccessTokenClientCredentials(scope, grantType);
        return new AuthenticationHeaderValue(AccessTokenType.Bearer, accessToken);
    }

    private async Task<AuthenticationHeaderValue> GetHeaderForResourceOwnerCredentials(string username, string password, string? scope, string grantType)
    {
        var accessToken = await GetAccessTokenResourceOwnerCredentials(username, password, scope, grantType);
        return new AuthenticationHeaderValue(AccessTokenType.Bearer, accessToken);
    }

    private async Task<string> GetAccessTokenAuthorizationCode(string grantType)
    {
        var accessToken = _secureTokenStore.GetAccessToken(grantType);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var refreshToken = _secureTokenStore.GetRefreshToken(grantType);
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new ArgumentException("Missing access token and refresh token");
        }

        var secureToken = await _authorizationService.RequestAccessToken(refreshToken!, null!);
        _secureTokenStore.Add(grantType, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private string GetAccessTokenImplicit(string grantType)
    {
        var accessToken = _secureTokenStore.GetAccessToken(grantType);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private async Task<string> GetAccessTokenClientCredentials(string? scope, string grantType)
    {
        var accessToken = _secureTokenStore.GetAccessToken(grantType);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var secureToken = await _authorizationService.RequestAccessToken(scope);
        _secureTokenStore.Add(grantType, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private async Task<string> GetAccessTokenResourceOwnerCredentials(string username, string password, string? scope, string grantType)
    {
        var accessToken = _secureTokenStore.GetAccessToken(grantType);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var secureToken = await _authorizationService.RequestAccessToken(username, password, scope);
        _secureTokenStore.Add(grantType, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }
}