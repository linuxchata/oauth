namespace Shark.Sample.ProtectedResource.Models;

public sealed class AuthorizationClientConfiguration
{
    public const string Name = nameof(AuthorizationClientConfiguration);

    public required string Issuer { get; set; }

    public required string Audience { get; set; }
}