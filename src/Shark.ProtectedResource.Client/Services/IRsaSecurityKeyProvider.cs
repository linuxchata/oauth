using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.Client.Services;

public interface IRsaSecurityKeyProvider
{
    Task<RsaSecurityKey> GetRsaSecurityKey();
}