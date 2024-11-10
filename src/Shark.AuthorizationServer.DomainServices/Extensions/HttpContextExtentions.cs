using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.DomainServices.Extensions;

namespace Shark.AuthorizationServer.DomainServices.Extensions;

public static class HttpContextExtentions
{
    public static async Task SignInAsync(
        this HttpContext context,
        string userName,
        string? authMethod = null)
    {
        var claims = CreateClaims(userName, authMethod);

        var userIdentity = CreateUserIdentity(claims);

        await context.SignInAsync(Scheme.Cookies, userIdentity);
    }

    private static List<Claim> CreateClaims(string userName, string? authMethod)
    {
        var claims = new List<Claim>();

        // Add user identifier
        var userId = Guid.NewGuid().ToString();
        claims.Add(new(JwtRegisteredClaimNames.Sub, userId));

        // Add user name
        if (!string.IsNullOrWhiteSpace(userName))
        {
            claims.Add(new(JwtRegisteredClaimNames.Name, userName));
        }

        // Add authentication methods references
        if (!string.IsNullOrWhiteSpace(authMethod))
        {
            claims.Add(new(JwtRegisteredClaimNames.Amr, authMethod));
        }

        return claims;
    }

    private static ClaimsPrincipal CreateUserIdentity(List<Claim> claims)
    {
        var userIdentity = new ClaimsIdentity(
            claims,
            Scheme.Cookies,
            JwtRegisteredClaimNames.Name,
            null!);

        return new ClaimsPrincipal(userIdentity);
    }
}
