namespace Shark.AuthorizationServer.Services;

public interface IStringGeneratorService
{
    string GenerateCode(byte length = 40);

    string GenerateRefreshToken(byte length = 64);
}