namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IRefreshTokenGeneratorService
{
    string? Generate(string[] scopes);
}
