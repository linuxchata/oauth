using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public class AccessTokenGeneratorService : IAccessTokenGeneratorService
{
    private readonly AuthorizationServerConfiguration _configuration;

    public AccessTokenGeneratorService(IOptions<AuthorizationServerConfiguration> options)
    {
        _configuration = options.Value;
    }

    public string Generate(string userId, string[] scopes)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(nameof(userId));
        ArgumentNullException.ThrowIfNull(nameof(scopes));

        var claims = new Claim[]
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new("scope", string.Join(" ", scopes)),
        };

        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        var securityAlgorithms = _configuration.SecurityAlgorithms ?? SecurityAlgorithms.HmacSha256;
        var signingCredentials = new SigningCredentials(securityKey, securityAlgorithms);

        var dateTimeNow = DateTime.Now;
        var token = new JwtSecurityToken(
            issuer: _configuration.Issuer ?? "Issuer",
            audience: "audience",
            claims: claims,
            notBefore: dateTimeNow,
            expires: dateTimeNow.AddSeconds(_configuration.AccessTokenExpirationInSeconds),
            signingCredentials: signingCredentials
        );

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            token.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}