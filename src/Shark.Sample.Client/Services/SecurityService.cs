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

    private const string AuthorizeEndpoint = "http://localhost:9000/authorize";
    private const string TokenEndpoint = "http://localhost:9000/token";
    private const string ClientCallbackEndpoint = "http://localhost:9001/callback";
    private const string ClientRedirectUrl = "http://localhost:9001";

    private readonly string _clientId = "client-1";
    private readonly string _clientSecret = "client-secret-01";
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly ILogger<SecurityService> _logger = logger;

    public string BuildAuthorizeUrl(string state)
    {
        var uriBuilder = new UriBuilder(AuthorizeEndpoint);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);
        query["response_type"] = ResponseType;
        query["client_id"] = _clientId;
        query["redirect_url"] = ClientCallbackEndpoint;
        query["state"] = state;
        uriBuilder.Query = query.ToString();
        return uriBuilder.ToString();
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
            new("code", code),
            new("scope", scope),
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