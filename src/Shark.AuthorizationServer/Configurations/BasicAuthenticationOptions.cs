using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Core.Configurations;

public sealed class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(AuthenticationSchemeOptions);
}