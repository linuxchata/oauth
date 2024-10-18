using System.Security.Claims;
using Shark.AuthorizationServer.Core.Constants;

namespace Shark.AuthorizationServer.Core.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static bool HasScope(this ClaimsPrincipal claimsPrincipal, string scope)
    {
        return claimsPrincipal.Claims.Any(c =>
            string.Equals(c.Type, Scope.Name, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(c.Value, scope, StringComparison.OrdinalIgnoreCase));
    }
}