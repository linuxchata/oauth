namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IAccessTokenGeneratorService
{
    string Generate(string? userId, string? userName, string[] scopes, string audience);
}