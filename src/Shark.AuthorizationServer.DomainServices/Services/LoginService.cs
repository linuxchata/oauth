﻿using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class LoginService(
    IHttpContextAccessor httpContextAccessor) : ILoginService
{
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public async Task SignIn(string userName, string[] selectedScopes)
    {
        var claims = CreateClaims(userName, selectedScopes);

        var claimsPrincipal = CreateClaimsPrincipal(claims);

        if (_httpContextAccessor.HttpContext != null)
        {
            await _httpContextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                claimsPrincipal);
        }
    }

    private static List<Claim> CreateClaims(string userName, string[] selectedScopes)
    {
        var claims = new List<Claim>();

        // Add user name claim
        if (!string.IsNullOrWhiteSpace(userName))
        {
            claims.Add(new(JwtRegisteredClaimNames.Name, userName));
        }

        // Add scopes claims
        if (selectedScopes != null && selectedScopes.Length != 0)
        {
            claims.Add(new(ClaimType.Scope, string.Join(' ', selectedScopes)));
        }

        return claims;
    }

    private static ClaimsPrincipal CreateClaimsPrincipal(List<Claim> claims)
    {
        var claimsIdentity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme,
            JwtRegisteredClaimNames.Name,
            null!);

        return new ClaimsPrincipal(claimsIdentity);
    }
}
