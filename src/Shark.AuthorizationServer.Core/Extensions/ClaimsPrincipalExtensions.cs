using System.Security.Claims;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Constants;

namespace Shark.AuthorizationServer.Core.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static bool HasScope(this ClaimsPrincipal claimsPrincipal, string scope)
    {
        return claimsPrincipal.Claims.Any(c => c.Type.EqualsTo(Scope.Name) && c.Value.EqualsTo(scope));
    }
}