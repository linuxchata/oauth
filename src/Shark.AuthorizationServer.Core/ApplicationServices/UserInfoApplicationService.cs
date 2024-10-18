using System.Security.Claims;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Responses;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class UserInfoApplicationService : IUserInfoApplicationService
{
    public UserInfoBaseResponse Execute(ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(claimsPrincipal, nameof(claimsPrincipal));

        if (!claimsPrincipal.Claims.Any(c =>
            string.Equals(c.Type, Scope.Name, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(c.Value, Scope.OpenId, StringComparison.OrdinalIgnoreCase)))
        {
            return new UserInfoForbiddenResponse();
        }

        return new UserInfoResponse();
    }
}
