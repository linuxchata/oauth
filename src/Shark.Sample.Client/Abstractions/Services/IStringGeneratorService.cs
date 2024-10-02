namespace Shark.Sample.Client.Abstractions.Services;

public interface IStringGeneratorService
{
    string GenerateCodeVerifier(byte length = 83);
}