using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.Common.Abstractions;

public interface ICustomAccessTokenHandler
{
    JwtSecurityToken? Read(string accessToken, TokenValidationParameters? tokenValidationParameters);
}