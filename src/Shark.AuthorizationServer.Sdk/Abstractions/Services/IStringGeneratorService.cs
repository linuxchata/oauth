namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IStringGeneratorService
{
    string GenerateCodeVerifier(byte length = 83);
}