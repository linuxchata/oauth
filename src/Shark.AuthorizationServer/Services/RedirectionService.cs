using System.Web;

namespace Shark.AuthorizationServer.Services;

public sealed class RedirectionService : IRedirectionService
{
    public string BuildRedirectUrl(string redirectUrl, string code, string[] scopes, string state)
    {
        var uriBuilder = new UriBuilder(redirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[nameof(code)] = code;

        if (scopes != null && scopes.Length != 0)
        {
            query["scope"] = string.Join(' ', scopes);
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[nameof(state)] = state;
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }
}
