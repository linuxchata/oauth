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
        // Parse parameters from query string to rebuild URL to Autorize endpoint
        var returnUri = new Uri("http://localhost/" + returnUrl); // Fix issue with parsing query string
        var returnUriQueryString = returnUri.Query;
        var code = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ResponseType);
        var clientId = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ClientId);
        var state = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.State);
        var redirectUrl = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.RedirectUrl);

        // Rebuild URL to Autorize endpoint (mostly validation purpose)
        var uriBuilder = new UriBuilder(authorizationServerUri)
        {
            Path = returnUri.LocalPath,
        };

        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        if (!string.IsNullOrWhiteSpace(code))
        {
            query[QueryParam.ResponseType] = code;
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
}
