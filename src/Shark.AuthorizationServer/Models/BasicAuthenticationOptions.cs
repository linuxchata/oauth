using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Models;

public class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(AuthenticationSchemeOptions);
}