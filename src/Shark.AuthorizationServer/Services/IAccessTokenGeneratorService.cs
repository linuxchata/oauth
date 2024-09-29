namespace Shark.AuthorizationServer.Services;

public interface IAccessTokenGeneratorService
{
    string Generate(string? userId, string? userName, string[] scopes, string audience);
}