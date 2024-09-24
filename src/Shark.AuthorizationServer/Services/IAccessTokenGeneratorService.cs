namespace Shark.AuthorizationServer.Services;

public interface IAccessTokenGeneratorService
{
    string Generate(string userId, string[] scopes);
}