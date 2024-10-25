using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class StringGeneratorService : IStringGeneratorService
{
    private const string AuthorizationCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private const string RefreshTokenChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string ClientSecretChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private const string ClientAccessTokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string UserDeviceCodeChars = "0123456789";
    private const string DeviceCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz_0123456789";

    private static readonly Random Random = new();

    public string GenerateCode(byte length = 40)
    {
        return GenerateInternal(AuthorizationCodeChars, length);
    }

    public string GenerateRefreshToken(byte length = 64)
    {
        return GenerateInternal(RefreshTokenChars, length);
    }

    public string GenerateClientSecret(byte length = 18)
    {
        return GenerateInternal(ClientSecretChars, length);
    }

    public string GenerateClientAccessToken(byte length = 42)
    {
        return GenerateInternal(ClientAccessTokenChars, length);
    }

    public string GenerateDeviceCode(byte length = 47)
    {
        return GenerateInternal(DeviceCodeChars, length);
    }

    public string GenerateUserDeviceCode(byte length = 6)
    {
        return GenerateInternal(UserDeviceCodeChars, length);
    }

    private static string GenerateInternal(string chars, byte length)
    {
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[Random.Next(s.Length)]).ToArray());
    }
}