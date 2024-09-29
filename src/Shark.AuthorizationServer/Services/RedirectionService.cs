using System.Web;
using Shark.AuthorizationServer.Constants;

namespace Shark.AuthorizationServer.Services;

public sealed class RedirectionService : IRedirectionService
{
    public string? GetClientId(string returnUrl)
    {
        return HttpUtility.ParseQueryString(returnUrl)?.Get(QueryParam.ClientId);
    }

    public string BuildAuthorizeUrl(
        string authorizationServerUri,
        string returnUrl,
        string[] scopes)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(authorizationServerUri);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(returnUrl);

        // Parse parameters from query string to rebuild URL to Autorize endpoint
        var returnUri = new Uri("http://localhost/" + returnUrl); // Fix issue with parsing query string
        var returnUriQueryString = returnUri.Query;
        var responseType = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ResponseType);
        var clientId = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ClientId);
        var state = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.State);
        var redirectUrl = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.RedirectUrl);

        // Rebuild URL to Autorize endpoint (mostly validation purpose)
        var uriBuilder = new UriBuilder(authorizationServerUri)
        {
            Path = returnUri.LocalPath,
        };

        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        if (!string.IsNullOrWhiteSpace(responseType))
        {
            query[QueryParam.ResponseType] = responseType;
        }

        if (!string.IsNullOrWhiteSpace(clientId))
        {
            query[QueryParam.ClientId] = clientId;
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[QueryParam.State] = state;
        }

        if (!string.IsNullOrWhiteSpace(redirectUrl))
        {
            query[QueryParam.RedirectUrl] = redirectUrl;
        }

        if (scopes != null && scopes.Length != 0)
        {
            query[QueryParam.Scope] = string.Join(' ', scopes);
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }

    public string BuildClientCallbackUrl(string redirectUrl, string code, string[] scopes, string? state)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(redirectUrl);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(code);

        var uriBuilder = new UriBuilder(redirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[nameof(code)] = code;

        if (scopes != null && scopes.Length != 0)
        {
            query[QueryParam.Scope] = string.Join(' ', scopes);
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[QueryParam.State] = state;
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }

    public string BuildClientCallbackUrl(string redirectUrl, string token, string tokenType)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(redirectUrl);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(token);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(tokenType);

        var uriBuilder = new UriBuilder(redirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[QueryParam.Token] = token;
        query[QueryParam.TokenType] = tokenType;

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }
}
