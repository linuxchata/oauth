using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Configurations;

public sealed class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(AuthenticationSchemeOptions);
}