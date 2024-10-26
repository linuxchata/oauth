using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.Sdk.Services;

public interface ISecurityKeyProvider
{
    Task<SecurityKey> GetSecurityKey();
}