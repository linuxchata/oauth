using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Extensions;
using Shark.AuthorizationServer.Core.Responses;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class UserInfoApplicationService : IUserInfoApplicationService
{
    public UserInfoBaseResponse Execute(ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(claimsPrincipal, nameof(claimsPrincipal));

        if (!claimsPrincipal.HasScope(Scope.OpenId))
        {
            return new UserInfoForbiddenResponse();
        }

        var response = new UserInfoResponse();

        if (claimsPrincipal.HasScope(Scope.Profile))
        {
            response.Subject = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        }

        if (claimsPrincipal.HasScope(Scope.Email))
        {
            response.Email = "username@example";
            response.EmailVerified = true;
        }

        if (claimsPrincipal.HasScope(Scope.Address))
        {
            response.Address = "23 Union Square W, New York, NY 10003, USA";
        }

        if (claimsPrincipal.HasScope(Scope.Phone))
        {
            response.PhoneNumber = "555443126";
            response.PhoneNumberVerified = true;
        }

        return response;
    }
}
