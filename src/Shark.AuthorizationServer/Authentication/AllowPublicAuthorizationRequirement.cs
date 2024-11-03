using Microsoft.AspNetCore.Authorization;

namespace Shark.AuthorizationServer.Authentication;

public sealed class AllowPublicAuthorizationRequirement :
    AuthorizationHandler<AllowPublicAuthorizationRequirement>,
    IAuthorizationRequirement
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AllowPublicAuthorizationRequirement requirement)
    {
        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}