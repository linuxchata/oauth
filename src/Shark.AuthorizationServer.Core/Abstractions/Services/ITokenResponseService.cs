using System.Security.Claims;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Services;

public interface ITokenResponseService
{
    (TokenResponse TokenResponse, string AccessTokenId) Generate(
        string clientId,
        string audience,
        string[] scopes,
        IEnumerable<CustomClaim>? claims = null);

    TokenResponse GenerateForAccessTokenOnly(string audience, string[] scopes, IEnumerable<CustomClaim>? claims = null);
}