using Microsoft.Extensions.Primitives;

namespace Shark.Sample.ProtectedResource.Services;

public static class AuthenticationService
{
    private const string HeaderKeyName = "Authorization";

    public static bool IsAuthenticated(IHeaderDictionary headers)
    {
        if (!headers.TryGetValue(HeaderKeyName, out StringValues headerValue))
        {
            return false;
        };

        if (headerValue == StringValues.Empty)
        {
            return false;
        }

        return true;
    }
}