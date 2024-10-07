namespace Shark.AuthorizationServer.Models;

public sealed class AuthorizationServerConfiguration
{
    public const string Name = nameof(AuthorizationServerConfiguration);

    public string Issuer { get; set; } = null!;

    public string SymmetricSecurityKey { get; set; } = null!;

    public string KeyId { get; set; } = null!;

    public string SecurityAlgorithms { get; set; } = null!;

    public int AccessTokenExpirationInSeconds { get; set; }
}