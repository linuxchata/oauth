using System.Web;

namespace Shark.AuthorizationServer.Services;

public sealed class RedirectionService : IRedirectionService
{
    private const string ResponseTypeQueryParameterName = "response_type";
    private const string ClientIdQueryParameterName = "client_id";
    private const string StateQueryParameterName = "state";
    private const string ScopeQueryParameterName = "scope";
    private const string RedirectUrlQueryParameterName = "redirect_url";

    public string? GetClientId(string returnUrl)
    {
        return HttpUtility.ParseQueryString(returnUrl)?.Get(ClientIdQueryParameterName);
    }

    public string BuildAuthorizeUrl(
        string authorizationServerUri,
        string returnUrl,
        string[] scopes)
    {
        // Parse parameters from query string to rebuild URL to Autorize endpoint
        var returnUri = new Uri("http://localhost/" + returnUrl); // Fix issue with parsing query string
        var returnUriQueryString = returnUri.Query;
        var code = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(ResponseTypeQueryParameterName);
        var clientId = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(ClientIdQueryParameterName);
        var state = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(StateQueryParameterName);
        var redirectUrl = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(RedirectUrlQueryParameterName);

        // Rebuild URL to Autorize endpoint (mostly validation purpose)
        var uriBuilder = new UriBuilder(authorizationServerUri)
        {
            Path = returnUri.LocalPath,
        };

        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        if (!string.IsNullOrWhiteSpace(code))
        {
            query[ResponseTypeQueryParameterName] = code;
        }

        if (!string.IsNullOrWhiteSpace(clientId))
        {
            query[ClientIdQueryParameterName] = clientId;
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[StateQueryParameterName] = state;
        }

        if (!string.IsNullOrWhiteSpace(redirectUrl))
        {
            query[RedirectUrlQueryParameterName] = redirectUrl;
        }

        if (scopes != null && scopes.Length != 0)
        {
            query[ScopeQueryParameterName] = string.Join(' ', scopes);
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }

    public string BuildClientCallbackUrl(string redirectUrl, string code, string[] scopes, string state)
    {
        var uriBuilder = new UriBuilder(redirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[nameof(code)] = code;

        if (scopes != null && scopes.Length != 0)
        {
            query[ScopeQueryParameterName] = string.Join(' ', scopes);
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[StateQueryParameterName] = state;
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }
}
