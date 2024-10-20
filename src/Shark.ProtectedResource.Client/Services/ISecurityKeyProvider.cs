using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.Client.Services;

public interface ISecurityKeyProvider
{
    Task<SecurityKey> GetSecurityKey();
}