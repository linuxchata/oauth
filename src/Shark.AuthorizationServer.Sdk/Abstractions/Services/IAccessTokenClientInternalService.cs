using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IAccessTokenClientInternalService
{
    Task<SecureToken> RequestForAuthorizationCodeFlow(string code, string? scope, string? state, string? expectedState, string? codeVerifier);

    Task<SecureToken> RequestForRefreshTokenFlow(string refreshToken, string? scope);

    Task<SecureToken> RequestForClientCredentialsFlow(string? scope);

    Task<SecureToken> RequestForPasswordFlow(string username, string password, string? scope);
}