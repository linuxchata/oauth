using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Models;

public sealed class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(AuthenticationSchemeOptions);
}