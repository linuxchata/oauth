namespace Shark.AuthorizationServer.Models;

public sealed class AuthorizationServerConfiguration
{
    public const string Name = nameof(AuthorizationServerConfiguration);

    public required string Issuer { get; set; }

    public required string SymmetricSecurityKey { get; set; }

    public required string KeyId { get; set; }

    public required string SecurityAlgorithms { get; set; }

    public int AccessTokenExpirationInSeconds { get; set; }
}