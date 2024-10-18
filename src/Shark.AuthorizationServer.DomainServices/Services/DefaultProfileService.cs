using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class DefaultProfileService : IProfileService
{
    public Task<ProfileInfo> Get(string userId)
    {
        var profileInfo = new ProfileInfo
        {
            Name = "John Doe",
            GivenName = "John",
            FamilyName = "Doe",
            Email = "username@example",
            EmailVerified = true,
            Address = "23 Union Square W, New York, NY 10003, USA",
            PhoneNumber = "555443126",
            PhoneNumberVerified = true,
        };

        return Task.FromResult(profileInfo);
    }
}
