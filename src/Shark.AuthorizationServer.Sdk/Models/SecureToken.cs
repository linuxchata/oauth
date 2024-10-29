namespace Shark.AuthorizationServer.Sdk.Models;

public record SecureToken(string? AccessToken, string? IdToken, string? RefreshToken)
{
}
