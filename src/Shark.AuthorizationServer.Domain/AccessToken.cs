namespace Shark.AuthorizationServer.Domain;

public sealed class AccessToken
{
    public required string Id { get; set; }

    public required string Value { get; set; }
}