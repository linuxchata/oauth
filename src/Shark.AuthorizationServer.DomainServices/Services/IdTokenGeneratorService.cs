using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Domain;
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

    public IdToken Generate(string userId, string? userName, string audience, string[] scopes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId, nameof(userId));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        if (!HasOpenIdScope(scopes))
        {
            return new IdToken();
        }

        var currentTime = DateTime.UtcNow;

        var claims = CreateClaims(userId, userName, audience, currentTime);

        return GenerateToken(claims);
    }

    private bool HasOpenIdScope(string[] scopes)
    {
        return scopes.Any(s => s.EqualsTo(OpenIdConnectScope.OpenId));
    }

    private List<Claim> CreateClaims(string userId, string? userName, string audience, DateTime currentTime)
    {
        var issuer = _configuration.Issuer;
        var issuedAt = EpochTime.GetIntDate(currentTime.ToUniversalTime()).ToString();
        var expireAt = EpochTime.GetIntDate(currentTime.AddMinutes(5).ToUniversalTime()).ToString();

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

    private IdToken GenerateToken(List<Claim> claims)
    {
        var signingCredentials = _signingCredentialsService.GetSigningCredentials();

        var jwtSecurityToken = new JwtSecurityToken(claims: claims, signingCredentials: signingCredentials);

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            jwtSecurityToken.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        var token = jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);

        return new IdToken { Value = token };
    }
}
