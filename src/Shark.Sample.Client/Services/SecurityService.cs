using System.Web;
using Newtonsoft.Json;
using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class SecurityService(
    IHttpClientFactory httpClientFactory,
    ILogger<SecurityService> logger) : ISecurityService
{
    private const string ResponseType = "code";
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const string RefreshTokenGrantType = "refresh_token";

    private const string LoginPage = "http://localhost:9000/login";
    private const string AuthorizeEndpoint = "authorize";
    private const string TokenEndpoint = "http://localhost:9000/token";
    private const string ClientCallbackEndpoint = "http://localhost:9001/callback";
    private const string ClientRedirectUrl = "http://localhost:9001";

    private readonly string _clientId = "client-1";
    private readonly string _clientSecret = "client-secret-01";
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly ILogger<SecurityService> _logger = logger;

    public string BuildLoginPageUrl(string state)
    {
        var returnUrlBuilder = new UriBuilder(null, AuthorizeEndpoint);
        var returnUrlBuilderQuery = HttpUtility.ParseQueryString(returnUrlBuilder.Query);
        returnUrlBuilderQuery["response_type"] = ResponseType;
        returnUrlBuilderQuery["client_id"] = _clientId;
        returnUrlBuilderQuery["redirect_url"] = ClientCallbackEndpoint;
        returnUrlBuilderQuery["state"] = state;
        returnUrlBuilder.Query = returnUrlBuilderQuery.ToString();
        var returnUrl = returnUrlBuilder.ToString();

        var loginPageUriBuilder = new UriBuilder(LoginPage);
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
            new("client_id", _clientId),
            new("client_secret", _clientSecret),
            new("grant_type", AuthorizationCodeGrantType),
            new("scope", scope),
            new("code", code),
            new("redirect_url", ClientRedirectUrl),
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
            new("client_id", _clientId),
            new("client_secret", _clientSecret),
            new("grant_type", RefreshTokenGrantType),
            new("scope", scope),
            new("refresh_token", refreshToken),
            new("redirect_url", ClientRedirectUrl),
        };

        return await RequestAccessTokenInternal(formData);
    }

    private async Task<SecureToken> RequestAccessTokenInternal(
        List<KeyValuePair<string, string>> formData)
    {
        var content = new FormUrlEncodedContent(formData);

        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(TokenEndpoint, content);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadAsStringAsync();
            var bearerToken = JsonConvert.DeserializeObject<BearerToken>(result);

            return new SecureToken(bearerToken?.AccessToken, bearerToken?.RefreshToken);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Unable to fetch bearer token from authorization server");
        }

        return new SecureToken(null, null);
    }
}