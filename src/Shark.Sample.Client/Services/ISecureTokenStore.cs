using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface ISecureTokenStore
{
    string? GetAccessToken(string key);

    string? GetRefreshToken(string key);

    void Add(string key, SecureToken secureToken);

    void RemoveAccessToken(string key);
}
