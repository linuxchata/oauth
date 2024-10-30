using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class AccessTokenClientInternalService(
    IHttpClientFactory httpClientFactory,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<AccessTokenClientInternalService> logger) : IAccessTokenClientInternalService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<AccessTokenClientInternalService> _logger = logger;

    public async Task<SecureToken> RequestForAuthorizationCodeFlow(
        string code,
        string? scope,
        string? state,
        string? expectedState,
        string? codeVerifier)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(code, nameof(code));

        if (!string.Equals(state, expectedState, StringComparison.Ordinal))
        {
            _logger.LogError("State does not match");
            return new SecureToken(null, null, null);
        }

        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.GrantType, GrantType.AuthorizationCode),
            new(QueryParam.Code, code),
            new(QueryParam.RedirectUri, _configuration.ClientCallbackEndpoint),
        };

        if (!string.IsNullOrWhiteSpace(scope))
        {
            formData.Add(new(QueryParam.Scope, scope));
        }

        if (!string.IsNullOrWhiteSpace(codeVerifier))
        {
            formData.Add(new(QueryParam.CodeVerifier, codeVerifier));
        }

        return await RequestAccessTokenInternal(formData);
    }

    public async Task<SecureToken> RequestForRefreshTokenFlow(string refreshToken, string? scope)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(refreshToken, nameof(refreshToken));

        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.GrantType, GrantType.RefreshToken),
            new(QueryParam.RefreshToken, refreshToken),
            new(QueryParam.RedirectUri, _configuration.ClientCallbackEndpoint),
        };

        if (!string.IsNullOrWhiteSpace(scope))
        {
            formData.Add(new(QueryParam.Scope, scope));
        }

        return await RequestAccessTokenInternal(formData);
    }

    public async Task<SecureToken> RequestForClientCredentialsFlow(string? scope)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.GrantType, GrantType.ClientCredentials),
        };

        if (!string.IsNullOrWhiteSpace(scope))
        {
            formData.Add(new(QueryParam.Scope, scope));
        }

        return await RequestAccessTokenInternal(formData);
    }

    public async Task<SecureToken> RequestForPasswordFlow(string username, string password, string? scope)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.Username, username),
            new(QueryParam.Password, password),
            new(QueryParam.GrantType, GrantType.ResourceOwnerCredentials),
        };

        if (!string.IsNullOrWhiteSpace(scope))
        {
            formData.Add(new(QueryParam.Scope, scope));
        }

        return await RequestAccessTokenInternal(formData);
    }

    private async Task<SecureToken> RequestAccessTokenInternal(List<KeyValuePair<string, string>> formData)
    {
        var tokenEndpointUri = BuildTokenEndpointUri();

        var content = new FormUrlEncodedContent(formData);

        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = GetAuthorizationHeaderValue();
            var response = await httpClient.PostAsync(tokenEndpointUri, content);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadAsStringAsync();
            var bearerToken = JsonSerializer.Deserialize<BearerToken>(result);

            _logger.LogInformation("Bearer token has been fetched from authorization server");

            return new SecureToken(bearerToken?.AccessToken, bearerToken?.IdToken, bearerToken?.RefreshToken);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(
                ex,
                "Unable to fetch Bearer token from authorization server. Status code is [{StatusCode}]",
                ex.StatusCode);
        }

        return new SecureToken(null, null, null);
    }

    private string BuildTokenEndpointUri()
    {
        var tokenEndpointUriBuilder = new UriBuilder(_configuration.Address)
        {
            Path = AuthorizationServerEndpoint.Token,
        };

        return tokenEndpointUriBuilder.ToString();
    }

    private AuthenticationHeaderValue GetAuthorizationHeaderValue()
    {
        var credentials = Encoding.UTF8.GetBytes(_configuration.ClientId + ":" + _configuration.ClientSecret);
        var encodedCredentials = Convert.ToBase64String(credentials);
        return new AuthenticationHeaderValue("Basic", encodedCredentials);
    }
}