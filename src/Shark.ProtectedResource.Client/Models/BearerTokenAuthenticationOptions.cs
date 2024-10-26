using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Sdk.Models;

public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = nameof(BearerTokenAuthenticationOptions);

    public string AuthorizationServerUri { get; set; } = null!;

    public string Issuer { get; set; } = null!;

    public bool ValidateIssuer { get; set; }

    public string Audience { get; set; } = null!;

    public bool ValidateAudience { get; set; }

    public string KeyId { get; set; } = null!;

    public string SymmetricSecurityKey { get; set; } = null!;
}