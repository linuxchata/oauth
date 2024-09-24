using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public sealed class SecureTokenStore : ISecureTokenStore
{
    private SecureToken? _storedSecureToken;

    public string? GetAccessToken()
    {
        return _storedSecureToken?.AccessToken;
    }

    public string? GetRefreshToken()
    {
        return _storedSecureToken?.RefreshToken;
    }

    public void Add(SecureToken secureToken)
    {
        _storedSecureToken = secureToken;
    }

    public void RemoveAccessToken()
    {
        _storedSecureToken = new SecureToken(null, _storedSecureToken?.RefreshToken);
    }
}
