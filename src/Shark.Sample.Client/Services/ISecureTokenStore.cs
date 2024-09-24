using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface ISecureTokenStore
{
    string? GetAccessToken();

    string? GetRefreshToken();

    void Add(SecureToken secureToken);

    void RemoveAccessToken();
}
