using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class AccessTokenGeneratorService(
    RsaSecurityKey rsaSecurityKey,
    IOptions<AuthorizationServerConfiguration> options) : IAccessTokenGeneratorService
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string Generate(string? userId, string? userName, string[] scopes, string audience)
    {
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));

        var currentTime = DateTime.UtcNow;

        var claims = CreateClaims(userId, userName, scopes, currentTime);

        var signingCredentials = GenerateSigningCredentials();

        var token = GenerateToken(claims, audience, signingCredentials, currentTime);

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

    private SigningCredentials GenerateSigningCredentials()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GenerateSigningCredentialsHs256();
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return GenerateSigningCredentialsRsa256();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }

    private SigningCredentials GenerateSigningCredentialsHs256()
    {
        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    }

    private SigningCredentials GenerateSigningCredentialsRsa256()
    {
        return new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
        };
    }

    private string GenerateToken(List<Claim> claims, string audience, SigningCredentials signingCredentials, DateTime currentTime)
    {
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