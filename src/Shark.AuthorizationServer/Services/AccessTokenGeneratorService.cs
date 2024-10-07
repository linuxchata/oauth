using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;

namespace Shark.AuthorizationServer.Services;

public sealed class AccessTokenGeneratorService(
    IOptions<AuthorizationServerConfiguration> options) : IAccessTokenGeneratorService
{
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string Generate(string? userId, string? userName, string[] scopes, string audience)
    {
        ArgumentNullException.ThrowIfNull(nameof(scopes));
        ArgumentNullException.ThrowIfNullOrWhiteSpace(nameof(audience));

        var claims = CreateClaims(userId, userName, scopes);

        using var disposibleObject = GenerateSigningCredentials(out SigningCredentials signingCredentials);

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

    private IDisposable GenerateSigningCredentials(out SigningCredentials signingCredentials)
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GenerateSigningCredentialsHs256(out signingCredentials);
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return GenerateSigningCredentialsRsa256(out signingCredentials);
        }

        throw new InvalidOperationException($"Unsupported security algorithms {_configuration.SecurityAlgorithms}");
    }

    private IDisposable GenerateSigningCredentialsHs256(out SigningCredentials signingCredentials)
    {
        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        return null!;
    }

    private IDisposable GenerateSigningCredentialsRsa256(out SigningCredentials signingCredentials)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(ReadRsa256PrivateKey());

        var securityKey = new RsaSecurityKey(rsa);
        signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        return rsa;
    }

    private string ReadRsa256PrivateKey()
    {
        return File.ReadAllText("Keys/RS256.Private.pem");
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