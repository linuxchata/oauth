using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Abstractions.Services;

public interface IAuthorizationService
{
    string BuildLoginPageUrl(string responseType, string? state, ProofKeyForCodeExchange? pkce = null);

    Task<SecureToken> RequestAccessToken(string code, string? scope, string? state, string? expectedState, string? codeVerifier);

    Task<SecureToken> RequestAccessToken(string refreshToken, string? scope);

    Task<SecureToken> RequestAccessToken(string? scope);

    Task<SecureToken> RequestAccessToken(string username, string password, string? scope);
}