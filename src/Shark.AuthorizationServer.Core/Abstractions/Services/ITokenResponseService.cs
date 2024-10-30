using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Services;

public interface ITokenResponseService
{
    (TokenResponse TokenResponse, AccessToken AccessToken) Generate(
        string clientId,
        string audience,
        string[] scopes,
        string userId,
        string? userName = null);

    TokenResponse GenerateForAccessTokenOnly(string audience, string[] scopes, string? userId = null);
}