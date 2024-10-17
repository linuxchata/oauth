namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IIdTokenGeneratorService
{
    string? Generate(string userId, string audience, string[] scopes);
}