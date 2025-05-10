using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Configurations;

namespace Shark.AuthorizationServer.Authentication;

public sealed class NoneAuthenticationHandler(
    IOptionsMonitor<NoneAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<NoneAuthenticationOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authenticationTicket = new AuthenticationTicket(new ClaimsPrincipal(), Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(authenticationTicket));
    }
}