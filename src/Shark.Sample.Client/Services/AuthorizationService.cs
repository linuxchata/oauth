using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class AuthorizationService(
    IHttpClientFactory httpClientFactory,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<AuthorizationService> logger) : IAuthorizationService
{
    private const string LoginPagePath = "login";
    private const string AuthorizeEndpointPath = "authorize";
    private const string TokenEndpointPath = "token";

    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<AuthorizationService> _logger = logger;

    public string BuildLoginPageUrl(string responseType, string? state, ProofKeyForCodeExchange? pkce = null)
    {
        // Create Return URL
        var returnUrlBuilder = new UriBuilder(null, AuthorizeEndpointPath);
        var returnUrlBuilderQuery = HttpUtility.ParseQueryString(returnUrlBuilder.Query);
        returnUrlBuilderQuery[QueryParam.ResponseType] = responseType;
        returnUrlBuilderQuery[QueryParam.ClientId] = _configuration.ClientId;
        returnUrlBuilderQuery[QueryParam.RedirectUri] = _configuration.ClientCallbackEndpoint;
        returnUrlBuilderQuery[QueryParam.State] = state;

        if (pkce != null)
        {
            returnUrlBuilderQuery[QueryParam.CodeChallenge] = pkce.CodeChallenge;
            returnUrlBuilderQuery[QueryParam.CodeChallengeMethod] = pkce.CodeChallengeMethod;
        }

        returnUrlBuilder.Query = returnUrlBuilderQuery.ToString();
        var returnUrl = returnUrlBuilder.ToString();

        // Create authorization server login page URL
        var loginPageUriBuilder = new UriBuilder(_configuration.Address)
        {
            Path = LoginPagePath,
        };
        var query = HttpUtility.ParseQueryString(loginPageUriBuilder.Query);
        query[QueryParam.ReturnUrl] = returnUrl;
        loginPageUriBuilder.Query = query.ToString();
        return loginPageUriBuilder.ToString();
    }

    /// <summary>
    /// Request access token for authorization_code flow
    /// </summary>
    public async Task<SecureToken> RequestAccessToken(
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

    /// <summary>
    /// Request access token for refresh_token flow
    /// </summary>
    public async Task<SecureToken> RequestAccessToken(string refreshToken, string? scope)
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

    /// <summary>
    /// Request access token for client_credentials flow
    /// </summary>
    public async Task<SecureToken> RequestAccessToken(string? scope)
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

    /// <summary>
    /// Request access token for password flow
    /// </summary>
    public async Task<SecureToken> RequestAccessToken(string username, string password, string? scope)
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
            Path = TokenEndpointPath,
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