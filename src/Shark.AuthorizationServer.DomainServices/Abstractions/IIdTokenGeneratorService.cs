using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IIdTokenGeneratorService
{
    IdToken Generate(string audience, string[] scopes, IEnumerable<CustomClaim>? claims = null);
}