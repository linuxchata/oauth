using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Shark.Sample.ProtectedResource.Constants;
using Shark.Sample.ProtectedResource.Models;
using Shark.Sample.ProtectedResource.Services;

namespace Shark.Sample.ProtectedResource.Authentication;

public sealed class BearerTokenAuthenticationHandler(
    IBearerTokenHandlingService bearerTokenHandlingService,
    IOptionsMonitor<BearerTokenAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<BearerTokenAuthenticationOptions>(options, logger, encoder)
{
    private readonly IBearerTokenHandlingService _bearerTokenHandlingService = bearerTokenHandlingService;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var accessToken = _bearerTokenHandlingService.GetAccessToken(Request.Headers);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
        }

        if (!_bearerTokenHandlingService.ParseAndValidateAccessToken(accessToken, out TokenIdentity tokenIdentity))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
        }

        var authenticationTicket = new AuthenticationTicket(CreateClaimsPrincipal(tokenIdentity), Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(authenticationTicket));
    }

    private ClaimsPrincipal CreateClaimsPrincipal(TokenIdentity tokenIdentity)
    {
        var claims = new List<Claim>();

        // Add user identifier claim
        if (!string.IsNullOrWhiteSpace(tokenIdentity.UserId))
        {
            claims.Add(new(ClaimType.Subject, tokenIdentity.UserId));
        }

        // Add scopes claims
        var scopeClaims = tokenIdentity.Scopes?.Select(s => new Claim(ClaimType.Scope, s)) ?? [];
        claims.AddRange(scopeClaims);

        var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
        return new ClaimsPrincipal(claimsIdentity);
    }
}