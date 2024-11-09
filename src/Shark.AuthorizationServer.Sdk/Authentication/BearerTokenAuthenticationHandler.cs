using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Configurations;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Authentication;

public sealed class BearerTokenAuthenticationHandler(
    IBearerTokenHandler bearerTokenHandler,
    IOptionsMonitor<BearerTokenAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<BearerTokenAuthenticationOptions>(options, logger, encoder)
{
    private readonly IBearerTokenHandler _bearerTokenHandler = bearerTokenHandler;

    protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var accessToken = _bearerTokenHandler.GetAccessToken(Request.Headers);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var tokenIdentity = await _bearerTokenHandler.ParseAccessToken(accessToken);
        if (tokenIdentity == null)
        {
            return AuthenticateResult.Fail("Unauthorized");
        }

        var claimsPrincipal = CreateClaimsPrincipal(tokenIdentity);
        var authenticationTicket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return AuthenticateResult.Success(authenticationTicket);
    }

    private ClaimsPrincipal CreateClaimsPrincipal(TokenIdentity tokenIdentity)
    {
        var claims = new List<Claim>();

        // Add user identifier claim
        if (!string.IsNullOrWhiteSpace(tokenIdentity.UserId))
        {
            claims.Add(new Claim(ClaimType.Subject, tokenIdentity.UserId));
        }

        // Add scopes claims
        var scopeClaims = tokenIdentity.Scopes?.Select(s => new Claim(ClaimType.Scope, s)) ?? [];
        claims.AddRange(scopeClaims);

        var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
        return new ClaimsPrincipal(claimsIdentity);
    }
}