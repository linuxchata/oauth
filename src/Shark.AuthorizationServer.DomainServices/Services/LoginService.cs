using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class LoginService(
    IHttpContextAccessor httpContextAccessor) : ILoginService
{
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public async Task SignIn(string userName, string[] scopes, string authMethod)
    {
        var claims = CreateClaims(userName, scopes, authMethod);

        var claimsPrincipal = CreateClaimsPrincipal(claims);

        if (_httpContextAccessor.HttpContext != null)
        {
            await _httpContextAccessor.HttpContext.SignInAsync(Scheme.Cookies, claimsPrincipal);
        }
    }

    private static List<Claim> CreateClaims(string userName, string[] scopes, string authMethod)
    {
        var claims = new List<Claim>();

        // Add user identifier claim
        var userId = Guid.NewGuid().ToString();
        claims.Add(new(JwtRegisteredClaimNames.Sub, userId));

        // Add user name
        if (!string.IsNullOrWhiteSpace(userName))
        {
            claims.Add(new(JwtRegisteredClaimNames.Name, userName));
        }

        // Add scopes claims
        if (scopes != null && scopes.Length != 0)
        {
            claims.Add(new(ClaimType.Scope, string.Join(' ', scopes)));
        }

        // Add authentication methods references
        if (!string.IsNullOrWhiteSpace(authMethod))
        {
            claims.Add(new(JwtRegisteredClaimNames.Amr, authMethod));
        }

        return claims;
    }

    private static ClaimsPrincipal CreateClaimsPrincipal(List<Claim> claims)
    {
        var claimsIdentity = new ClaimsIdentity(
            claims,
            Scheme.Cookies,
            JwtRegisteredClaimNames.Name,
            null!);

        return new ClaimsPrincipal(claimsIdentity);
    }
}
