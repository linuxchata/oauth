using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IIdTokenGeneratorService
{
    IdToken Generate(string userId, string? userName, string audience, string[] scopes);
}