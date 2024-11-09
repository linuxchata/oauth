using System.Security.Claims;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IAccessTokenGeneratorService
{
    AccessToken Generate(string[] scopes, string audience, IEnumerable<CustomClaim>? claims = null);
}