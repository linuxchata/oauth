using System.Web;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

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
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizationServerUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(returnUrl);

        // Parse parameters from query string to rebuild URL to Autorize endpoint
        // TODO: Review need for localhost
        var returnUri = new Uri("http://localhost/" + returnUrl); // Fix issue with parsing query string
        var returnUriQueryString = returnUri.Query;
        var responseType = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ResponseType);
        var clientId = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.ClientId);
        var state = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.State);
        var codeChallenge = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.CodeChallenge);
        var codeChallengeMethod = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.CodeChallengeMethod);
        var redirectUrl = HttpUtility.ParseQueryString(returnUriQueryString)?.Get(QueryParam.RedirectUri);

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

        if (!string.IsNullOrWhiteSpace(codeChallenge))
        {
            query[QueryParam.CodeChallenge] = codeChallenge;
        }

        if (!string.IsNullOrWhiteSpace(codeChallengeMethod))
        {
            query[QueryParam.CodeChallengeMethod] = codeChallengeMethod;
        }

        if (!string.IsNullOrWhiteSpace(redirectUrl))
        {
            query[QueryParam.RedirectUri] = redirectUrl;
        }

        if (scopes != null && scopes.Length != 0)
        {
            query[QueryParam.Scope] = string.Join(' ', scopes);
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }

    public string BuildClientCallbackUrl(string redirectUri, string code, string[] scopes, string? state)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        var uriBuilder = new UriBuilder(redirectUri);
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

    public string BuildClientCallbackUrl(string redirectUri, string token, string tokenType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);

        var uriBuilder = new UriBuilder(redirectUri);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[QueryParam.Token] = token;
        query[QueryParam.TokenType] = tokenType;

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }
}
