using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public class AccessTokenGeneratorService(
    IOptions<AuthorizationServerConfiguration> options) : IAccessTokenGeneratorService
{
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string Generate(string? userId, string? userName, string[] scopes, string audience)
    {
        ArgumentNullException.ThrowIfNull(nameof(scopes));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(nameof(audience));

        var claims = CreateClaims(userId, userName, scopes);

        var signingCredentials = GenerateSigningCredentials();

        var token = GenerateToken(claims, audience, signingCredentials);

        return token;
    }

    private List<Claim> CreateClaims(string? userId, string? userName, string[] scopes)
    {
        var claims = new List<Claim>();

        if (!string.IsNullOrWhiteSpace(userId))
        {
            claims.Add(new(JwtRegisteredClaimNames.Sub, userId));
        }

        if (!string.IsNullOrWhiteSpace(userName))
        {
            claims.Add(new(JwtRegisteredClaimNames.Name, userName));
        }

        if (scopes.Length != 0)
        {
            claims.Add(new(ClaimType.Scope, string.Join(" ", scopes)));
        }

        return claims;
    }

    private SigningCredentials GenerateSigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        var securityAlgorithms = _configuration.SecurityAlgorithms ?? SecurityAlgorithms.HmacSha256;
        var signingCredentials = new SigningCredentials(securityKey, securityAlgorithms);

        return signingCredentials;
    }

    private string GenerateToken(List<Claim> claims, string audience, SigningCredentials signingCredentials)
    {
        var currentTime = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            issuer: _configuration.Issuer ?? "Issuer",
            audience: audience,
            claims: claims,
            notBefore: currentTime,
            expires: currentTime.AddSeconds(_configuration.AccessTokenExpirationInSeconds),
            signingCredentials: signingCredentials
        );

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            token.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}