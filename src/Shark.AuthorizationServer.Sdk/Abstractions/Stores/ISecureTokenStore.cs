using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Stores;

public interface ISecureTokenStore
{
    string? GetAccessToken(string key);

    string? GetRefreshToken(string key);

    void Add(string key, SecureToken secureToken);

    void RemoveAccessToken(string key);
}
