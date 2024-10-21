using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IAccessTokenGeneratorService
{
    AccessToken Generate(string? userId, string? userName, string[] scopes, string audience);
}