namespace Shark.AuthorizationServer.Domain;

public record RevokeToken(string TokenId, DateTime RevokedAt);