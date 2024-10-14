using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Configurations;

public sealed class ClientTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(AuthenticationSchemeOptions);
}