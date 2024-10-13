using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.ProtectedResource.Client.Constants;
using Shark.ProtectedResource.Client.Models;
using Shark.ProtectedResource.Client.Services;

namespace Shark.ProtectedResource.Client.Authentication;

public sealed class BearerTokenAuthenticationHandler : AuthenticationHandler<BearerTokenAuthenticationOptions>
{
    private readonly IBearerTokenHandlingService _bearerTokenHandlingService;

    public BearerTokenAuthenticationHandler(
        IBearerTokenHandlingService bearerTokenHandlingService,
        IOptionsMonitor<BearerTokenAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
        _bearerTokenHandlingService = bearerTokenHandlingService;
    }

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
            claims.Add(new Claim(ClaimType.Subject, tokenIdentity.UserId));
        }

        // Add scopes claims
        var scopeClaims = tokenIdentity.Scopes?.Select(s => new Claim(ClaimType.Scope, s)) ?? Enumerable.Empty<Claim>();
        claims.AddRange(scopeClaims);

        var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
        return new ClaimsPrincipal(claimsIdentity);
    }
}