using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Configurations;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;

namespace Shark.AuthorizationServer.Authentication;

public sealed class ClientTokenAuthenticationHandler(
    IClientRepository clientRepository,
    IOptionsMonitor<ClientTokenAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<ClientTokenAuthenticationOptions>(options, logger, encoder)
{
    private const string UnauthorizedMessage = "Unauthorized";

    private readonly IClientRepository _clientRepository = clientRepository;

    /// <summary>
    /// Handle authentication with client's RegistrationAccessToken.
    /// </summary>
    /// <returns>Authenticate result.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorizationHeaderValue = GetAndValidateAuthorizationHeader();
        if (string.IsNullOrWhiteSpace(authorizationHeaderValue))
        {
            return Task.FromResult(AuthenticateResult.Fail(UnauthorizedMessage));
        }

        if (!ValidateCredentials(authorizationHeaderValue))
        {
            return Task.FromResult(AuthenticateResult.Fail(UnauthorizedMessage));
        }

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(Scheme.Name));
        var authenticationTicket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(authenticationTicket));
    }

    private string? GetAndValidateAuthorizationHeader()
    {
        var authorizationHeaderValue = Request.Headers?.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorizationHeaderValue))
        {
            return null;
        }

        if (!authorizationHeaderValue.StartsWith(Constants.Scheme.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return authorizationHeaderValue.Trim();
    }

    private bool ValidateCredentials(string authorizationHeaderValue)
    {
        try
        {
            var clientId = Request.RouteValues["ClientId"]?.ToString();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                return false;
            }

            var startIndexOfAccessToken = authorizationHeaderValue.IndexOf(Constants.Scheme.Bearer) + 1;
            var accessToken = authorizationHeaderValue[(startIndexOfAccessToken + Constants.Scheme.Bearer.Length)..];

            var client = _clientRepository.Get(clientId);
            if (client is null || !string.Equals(client.RegistrationAccessToken, accessToken, StringComparison.Ordinal))
            {
                return false;
            }
        }
        catch (FormatException)
        {
            return false;
        }

        return true;
    }
}