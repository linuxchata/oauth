using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class AccessTokenGeneratorService(
    ISigningCredentialsService signingCredentialsService,
    IOptions<AuthorizationServerConfiguration> options) : IAccessTokenGeneratorService
{
    private readonly ISigningCredentialsService _signingCredentialsService = signingCredentialsService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string Generate(string? userId, string? userName, string[] scopes, string audience)
    {
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));

        var currentTime = DateTime.UtcNow;

        var claims = CreateClaims(userId, userName, scopes, currentTime);

        var token = GenerateToken(claims, audience, currentTime);

        return token;
    }

    private List<Claim> CreateClaims(string? userId, string? userName, string[] scopes, DateTime currentTime)
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

        var issuedAt = EpochTime.GetIntDate(currentTime.ToUniversalTime()).ToString();
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, issuedAt, ClaimValueTypes.Integer64));

        var jwtId = Guid.NewGuid().ToString().ToLower();
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, jwtId));

        return claims;
    }

    private string GenerateToken(List<Claim> claims, string audience, DateTime currentTime)
    {
        var signingCredentials = _signingCredentialsService.GenerateSigningCredentials();

        var token = new JwtSecurityToken(
            issuer: _configuration.IssuerUri ?? "Issuer",
            audience: audience,
            claims: claims,
            notBefore: currentTime,
            expires: currentTime.AddSeconds(_configuration.AccessTokenExpirationInSeconds),
            signingCredentials: signingCredentials);

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            token.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}