using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Services;

namespace Shark.AuthorizationServer.Authentication;

/// <summary>
/// RsaSecurityKey provider for authorization server itself.
/// </summary>
/// <param name="rsaSecurityKey">Represents a Rsa security key.</param>
public sealed class RsaSecurityKeyLocalProvider(
    [FromKeyedServices("public")] RsaSecurityKey rsaSecurityKey) : IRsaSecurityKeyProvider
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;

    public Task<RsaSecurityKey> GetRsaSecurityKey()
    {
        return Task.FromResult(_rsaSecurityKey);
    }
}
