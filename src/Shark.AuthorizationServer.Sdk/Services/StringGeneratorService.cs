using Shark.AuthorizationServer.Sdk.Abstractions.Services;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class StringGeneratorService : IStringGeneratorService
{
    private const string CodeVerifierChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijklmnopqrstuvwxyz";

    private static readonly Random Random = new();

    public string GenerateCodeVerifier(byte length = 43)
    {
        return new string(Enumerable.Repeat(CodeVerifierChars, length)
            .Select(s => s[Random.Next(s.Length)]).ToArray());
    }
}