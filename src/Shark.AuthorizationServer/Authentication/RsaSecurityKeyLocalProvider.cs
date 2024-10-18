using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Services;

namespace Shark.AuthorizationServer.Authentication;

public sealed class RsaSecurityKeyLocalProvider(RsaSecurityKey rsaSecurityKey) : IRsaSecurityKeyProvider
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;

    public Task<RsaSecurityKey> GetRsaSecurityKey()
    {
        return Task.FromResult(_rsaSecurityKey);
    }
}
