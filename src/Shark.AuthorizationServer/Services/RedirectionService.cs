using System.Web;

namespace Shark.AuthorizationServer.Services;

public sealed class RedirectionService : IRedirectionService
{
    public string BuildRedirectUrl(string redirectUrl, string code, string? scope, string state)
    {
        var uriBuilder = new UriBuilder(redirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);

        query[nameof(code)] = code;

        if (!string.IsNullOrWhiteSpace(scope))
        {
            query[nameof(scope)] = scope;
        }

        if (!string.IsNullOrWhiteSpace(state))
        {
            query[nameof(state)] = state;
        }

        uriBuilder.Query = query.ToString();

        return uriBuilder.ToString();
    }
}
