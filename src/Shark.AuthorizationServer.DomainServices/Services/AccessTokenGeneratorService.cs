using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class AccessTokenGeneratorService(
    ISigningCredentialsService signingCredentialsService,
    IOptions<AuthorizationServerConfiguration> options) : IAccessTokenGeneratorService
{
    private readonly ISigningCredentialsService _signingCredentialsService = signingCredentialsService;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public AccessToken Generate(string[] scopes, string audience, IEnumerable<CustomClaim>? claims = null)
    {
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));

        var currentTime = DateTime.UtcNow;

        var tokenClaims = CreateClaims(scopes, currentTime, claims);

        return GenerateToken(audience, tokenClaims, currentTime);
    }

    private static List<Claim> CreateClaims(string[] scopes, DateTime currentTime, IEnumerable<CustomClaim>? claims)
    {
        var tokenClaims = new List<Claim>();

        AddClaimIfExists(claims, JwtRegisteredClaimNames.Sub, tokenClaims);
        AddClaimIfExists(claims, JwtRegisteredClaimNames.Name, tokenClaims);
        AddAmrClaimIfExists(claims, tokenClaims);

        if (scopes.Length != 0)
        {
            tokenClaims.Add(new(ClaimType.Scope, string.Join(" ", scopes)));
        }

        var issuedAt = EpochTime.GetIntDate(currentTime.ToUniversalTime()).ToString();
        tokenClaims.Add(new Claim(JwtRegisteredClaimNames.Iat, issuedAt, ClaimValueTypes.Integer64));

        var jwtId = Guid.NewGuid().ToString().ToLower();
        tokenClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, jwtId));

        return tokenClaims;
    }

    private static void AddClaimIfExists(IEnumerable<CustomClaim>? claims, string claimName, List<Claim> tokenClaims)
    {
        var claim = claims?.FirstOrDefault(a => a.Type.EqualsTo(claimName));
        if (claim != null && !string.IsNullOrEmpty(claim.Value))
        {
            tokenClaims.Add(new(claimName, claim.Value));
        }
    }

    private static void AddAmrClaimIfExists(IEnumerable<CustomClaim>? claims, List<Claim> tokenClaims)
    {
        var claim = claims?.FirstOrDefault(a => a.Type.EqualsTo(JwtRegisteredClaimNames.Amr));
        if (claim != null && !string.IsNullOrEmpty(claim.Value))
        {
            var amrs = new List<string>();
            if (Amr.Supported.Contains(claim.Value))
            {
                amrs.Add(claim.Value);
            }
            else
            {
                amrs.Add(Amr.Custom);
            }

            var amrJson = JsonSerializer.Serialize(amrs);
            tokenClaims.Add(new(JwtRegisteredClaimNames.Amr, amrJson, JsonClaimValueTypes.JsonArray));
        }
    }

    private AccessToken GenerateToken(string audience, List<Claim> claims, DateTime currentTime)
    {
        var signingCredentials = _signingCredentialsService.GetSigningCredentials();

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _configuration.Issuer ?? "Issuer",
            audience: audience,
            claims: claims,
            notBefore: currentTime,
            expires: currentTime.AddSeconds(_configuration.AccessTokenExpirationInSeconds),
            signingCredentials: signingCredentials);

        if (!string.IsNullOrWhiteSpace(_configuration.KeyId))
        {
            jwtSecurityToken.Header.TryAdd(JwtHeaderParameterNames.Kid, _configuration.KeyId);
        }

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        var token = jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);

        return new AccessToken { Id = jwtSecurityToken.Id, Value = token };
    }
}