using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class IdTokenGeneratorService(
    ISigningCredentialsService signingCredentialsService,
    IOptions<AuthorizationServerConfiguration> options) : IIdTokenGeneratorService
{
    private readonly ISigningCredentialsService _signingCredentialsService = signingCredentialsService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string? Generate(string userId, string? userName, string audience, string[] scopes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        if (!HasOpenIdScope(scopes))
        {
            return null;
        }

        var currentTime = DateTime.UtcNow;

        var claims = CreateClaims(userId, userName, audience, currentTime);

        var token = GenerateToken(claims);

        return token;
    }

    private bool HasOpenIdScope(string[] scopes)
    {
        return scopes.Any(s => string.Equals(s, OpenIdConnectScope.OpenId, StringComparison.OrdinalIgnoreCase));
    }

    private List<Claim> CreateClaims(string userId, string? userName, string audience, DateTime currentTime)
    {
        var issuer = _configuration.Issuer;
        var issuedAt = EpochTime.GetIntDate(currentTime.ToUniversalTime()).ToString();
        var expireAt = EpochTime.GetIntDate(currentTime.AddHours(1).ToUniversalTime()).ToString();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
        };

        if (!string.IsNullOrWhiteSpace(userName))
        {
            claims.Add(new(JwtRegisteredClaimNames.Name, userName));
        }

        claims.Add(new(JwtRegisteredClaimNames.Iss, issuer));
        claims.Add(new(JwtRegisteredClaimNames.Aud, audience));
        claims.Add(new(JwtRegisteredClaimNames.Iat, issuedAt));
        claims.Add(new(JwtRegisteredClaimNames.Exp, expireAt));

        return claims;
    }

    private string GenerateToken(List<Claim> claims)
    {
        var signingCredentials = _signingCredentialsService.GenerateSigningCredentials();

        var token = new JwtSecurityToken(claims: claims, signingCredentials: signingCredentials);

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            token.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
