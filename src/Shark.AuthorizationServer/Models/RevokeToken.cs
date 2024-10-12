namespace Shark.AuthorizationServer.Models;

public record RevokeToken(string TokenId, DateTime RevokedAt);