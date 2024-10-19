namespace Shark.Sample.Client.Models;

public record SecureToken(string? AccessToken, string? IdToken, string? RefreshToken)
{
}
