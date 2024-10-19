using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Extensions;
using Shark.AuthorizationServer.Core.Responses.UserInfo;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class UserInfoApplicationService(
    IProfileService profileService) : IUserInfoApplicationService
{
    private readonly IProfileService _profileService = profileService;

    public async Task<UserInfoBaseResponse> Execute(ClaimsPrincipal claimsPrincipal)
    {
        ArgumentNullException.ThrowIfNull(claimsPrincipal, nameof(claimsPrincipal));

        if (!claimsPrincipal.HasScope(Scope.OpenId))
        {
            return new UserInfoForbiddenResponse();
        }

        var subject = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (string.IsNullOrEmpty(subject))
        {
            return new UserInfoBadRequestResponse();
        }

        var response = new UserInfoResponse();

        var profileData = await _profileService.Get(subject);

        if (profileData is null)
        {
            return new UserInfoNotFoundResponse();
        }

        if (claimsPrincipal.HasScope(Scope.Profile))
        {
            response.Subject = subject;
            response.Name = profileData.Name;
            response.GivenName = profileData.GivenName;
            response.FamilyName = profileData.FamilyName;
        }

        if (claimsPrincipal.HasScope(Scope.Email))
        {
            response.Email = profileData.Email;
            response.EmailVerified = profileData.EmailVerified;
        }

        if (claimsPrincipal.HasScope(Scope.Address))
        {
            response.Address = profileData.Address;
        }

        if (claimsPrincipal.HasScope(Scope.Phone))
        {
            response.PhoneNumber = profileData.PhoneNumber;
            response.PhoneNumberVerified = profileData.PhoneNumberVerified;
        }

        return response;
    }
}
