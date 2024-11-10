using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Extensions;
using Shark.AuthorizationServer.Core.Responses.UserInfo;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class UserInfoApplicationService(
    IProfileService profileService) : IUserInfoApplicationService
{
    private readonly IProfileService _profileService = profileService;

    public async Task<IUserInfoResponse> Execute(ClaimsPrincipal userIdentity)
    {
        ArgumentNullException.ThrowIfNull(userIdentity, nameof(userIdentity));

        if (!userIdentity.HasScope(Scope.OpenId))
        {
            return new UserInfoForbiddenResponse();
        }

        var subject = userIdentity.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (string.IsNullOrEmpty(subject))
        {
            return new UserInfoBadRequestResponse();
        }

        var response = new UserInfoResponse();

        var profileData = await _profileService.Get(subject);

        if (profileData == null)
        {
            return new UserInfoNotFoundResponse();
        }

        if (userIdentity.HasScope(Scope.Profile))
        {
            response.Subject = subject;
            response.Name = profileData.Name;
            response.FamilyName = profileData.FamilyName;
            response.GivenName = profileData.GivenName;
        }

        if (userIdentity.HasScope(Scope.Email))
        {
            response.Email = profileData.Email;
            response.EmailVerified = profileData.EmailVerified;
        }

        if (userIdentity.HasScope(Scope.Address))
        {
            response.Address = profileData.Address;
        }

        if (userIdentity.HasScope(Scope.Phone))
        {
            response.PhoneNumber = profileData.PhoneNumber;
            response.PhoneNumberVerified = profileData.PhoneNumberVerified;
        }

        return response;
    }
}
