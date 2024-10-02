using Shark.Sample.Client.Abstractions.Services;

namespace Shark.Sample.Client.Services;

public sealed class StringGeneratorService : IStringGeneratorService
{
    private const string CodeVerifierChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    private static readonly Random random = new();

    public string GenerateCodeVerifier(byte length = 83)
    {
        return new string(Enumerable.Repeat(CodeVerifierChars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }
}