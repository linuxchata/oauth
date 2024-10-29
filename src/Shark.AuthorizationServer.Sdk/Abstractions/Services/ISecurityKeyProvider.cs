using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface ISecurityKeyProvider
{
    Task<SecurityKey> GetSecurityKey();
}