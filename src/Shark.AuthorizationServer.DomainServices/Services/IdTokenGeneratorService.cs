using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class IdTokenGeneratorService(
    ISigningCredentialsService signingCredentialsService,
    IOptions<AuthorizationServerConfiguration> options) : IIdTokenGeneratorService
{
    private readonly ISigningCredentialsService _signingCredentialsService = signingCredentialsService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public IdToken Generate(string audience, string[] scopes, IEnumerable<CustomClaim>? claims = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        if (!HasOpenIdScope(scopes))
        {
            return new IdToken();
        }

        var currentTime = DateTime.UtcNow;

        var tokenClaims = CreateClaims(audience, currentTime, claims);

        return GenerateToken(tokenClaims);
    }

    private static bool HasOpenIdScope(IEnumerable<string> scopes)
    {
        return scopes.Any(s => s.EqualsTo(Scope.OpenId));
    }

    private List<Claim> CreateClaims(string audience, DateTime currentTime, IEnumerable<CustomClaim>? claims)
    {
        var issuer = _configuration.Issuer;
        var issuedAt = EpochTime.GetIntDate(currentTime.ToUniversalTime()).ToString();
        var expireAt = EpochTime.GetIntDate(currentTime.AddMinutes(5).ToUniversalTime()).ToString();

        var tokenClaims = new List<Claim>();

        AddClaimIfExists(claims, JwtRegisteredClaimNames.Sub, tokenClaims);
        AddClaimIfExists(claims, JwtRegisteredClaimNames.Name, tokenClaims);

        tokenClaims.Add(new(JwtRegisteredClaimNames.Iss, issuer));
        tokenClaims.Add(new(JwtRegisteredClaimNames.Aud, audience));
        tokenClaims.Add(new(JwtRegisteredClaimNames.Iat, issuedAt));
        tokenClaims.Add(new(JwtRegisteredClaimNames.Exp, expireAt));

        return tokenClaims;
    }

    private void AddClaimIfExists(IEnumerable<CustomClaim>? claims, string claimName, List<Claim> tokenClaims)
    {
        var claim = claims?.FirstOrDefault(a => a.Type.EqualsTo(claimName));
        if (claim != null && !string.IsNullOrEmpty(claim.Value))
        {
            tokenClaims.Add(new(claimName, claim.Value));
        }
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
