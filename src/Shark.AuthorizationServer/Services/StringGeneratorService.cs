namespace Shark.AuthorizationServer.Services;

public sealed class StringGeneratorService : IStringGeneratorService
{
    private const string AuthorizationCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private const string RefreshTokenChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static readonly Random random = new();

    public string GenerateCode(byte length = 40)
    {
        return GenerateInternal(AuthorizationCodeChars, length);
    }

    public string GenerateRefreshToken(byte length = 64)
    {
        return GenerateInternal(RefreshTokenChars, length);
    }

    private string GenerateInternal(string chars, byte length)
    {
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }
}