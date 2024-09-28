using System.Net.Http.Headers;
using System.Text;
using System.Web;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Shark.Sample.Client.Constants;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class SecurityService(
    IHttpClientFactory httpClientFactory,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<SecurityService> logger) : ISecurityService
{
    private const string LoginPagePath = "login";
    private const string AuthorizeEndpointPath = "authorize";
    private const string TokenEndpointPath = "token";

    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<SecurityService> _logger = logger;

    public string BuildLoginPageUrl(string state)
    {
        // Return URL
        var returnUrlBuilder = new UriBuilder(null, AuthorizeEndpointPath);
        var returnUrlBuilderQuery = HttpUtility.ParseQueryString(returnUrlBuilder.Query);
        returnUrlBuilderQuery["response_type"] = Security.ResponseType;
        returnUrlBuilderQuery["client_id"] = _configuration.ClientId;
        returnUrlBuilderQuery["redirect_url"] = _configuration.ClientCallbackEndpoint;
        returnUrlBuilderQuery["state"] = state;
        returnUrlBuilder.Query = returnUrlBuilderQuery.ToString();
        var returnUrl = returnUrlBuilder.ToString();

        // Authorization server login page
        var loginPageUriBuilder = new UriBuilder(_configuration.Address)
        {
            Path = LoginPagePath,
        };
        var query = HttpUtility.ParseQueryString(loginPageUriBuilder.Query);
        query["returnurl"] = returnUrl;
        loginPageUriBuilder.Query = query.ToString();
        return loginPageUriBuilder.ToString();
    }

    public async Task<SecureToken> RequestAccessToken(
        string code,
        string scope,
        string actualState,
        string expectedState)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            throw new ArgumentNullException(nameof(code));
        }

        if (!string.Equals(actualState, expectedState, StringComparison.Ordinal))
        {
            _logger.LogError("State does not match");
            return new SecureToken(null, null);
        }

        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.GrantType, Security.AuthorizationCodeGrantType),
            new(QueryParam.Scope, scope),
            new(QueryParam.Code, code),
            new(QueryParam.RedirectUrl, _configuration.ClientRedirectUrl),
        };

        return await RequestAccessTokenInternal(formData);
    }

    public async Task<SecureToken> RequestAccessToken(string refreshToken, string scope)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new ArgumentNullException(nameof(refreshToken));
        }

        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.ClientId, _configuration.ClientId),
            new(QueryParam.ClientSecret, _configuration.ClientSecret),
            new(QueryParam.GrantType, Security.RefreshTokenGrantType),
            new(QueryParam.Scope, scope),
            new(QueryParam.RefreshToken, refreshToken),
            new(QueryParam.RedirectUrl, _configuration.ClientRedirectUrl),
        };

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
            var bearerToken = JsonConvert.DeserializeObject<BearerToken>(result);

            _logger.LogInformation("Bearer token has been fetched from authorization server");

            return new SecureToken(bearerToken?.AccessToken, bearerToken?.RefreshToken);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(
                ex,
                $"Unable to fetch Bearer token from authorization server. Status code is {ex.StatusCode}");
        }

        return new SecureToken(null, null);
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