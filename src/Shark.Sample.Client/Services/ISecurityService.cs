using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface ISecurityService
{
    string BuildAuthorizeUrl(string state);

    Task<SecureToken> RequestAccessToken(string code, string actualState, string expectedState);

    Task<SecureToken> RequestAccessToken(string refreshToken);
}