using Microsoft.AspNetCore.Authentication;

namespace Shark.AuthorizationServer.Sdk.Configurations;

public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string Name = "BearerTokenAuthentication";

    public string AuthorizationServerUri { get; set; } = null!;

    public string Issuer { get; set; } = null!;

    public bool ValidateIssuer { get; set; }

    public string Audience { get; set; } = null!;

    public bool ValidateAudience { get; set; }

    public TokenIntrospectionOptions? TokenIntrospection { get; set; }

    public RetryOnGetConfigurationOptions? RetryConfiguration { get; set; }
}