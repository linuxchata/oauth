using Microsoft.AspNetCore.Authentication;

namespace Shark.Sample.ProtectedResource.Models;

public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(BearerTokenAuthenticationOptions);

    public string Issuer { get; set; }

    public string Audience { get; set; }
}