using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Configurations;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;

namespace Shark.AuthorizationServer.Authentication;

public sealed class BasicAuthenticationHandler(
    IClientRepository clientRepository,
    IOptionsMonitor<BasicAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<BasicAuthenticationOptions>(options, logger, encoder)
{
    private const string UnauthorizedMessage = "Unauthorized";

    private readonly IClientRepository _clientRepository = clientRepository;

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

        if (!authorizationHeaderValue.StartsWith(Constants.Scheme.Basic + ' ', StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return authorizationHeaderValue;
    }

    private bool ValidateCredentials(string authorizationHeaderValue)
    {
        try
        {
            var credentials = authorizationHeaderValue[Constants.Scheme.Basic.Length..].Trim();

            var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(credentials));

            var delimiterIndex = decodedCredentials.IndexOf(":", StringComparison.OrdinalIgnoreCase);
            if (delimiterIndex == -1)
            {
                return false;
            }

            var clientId = decodedCredentials[..delimiterIndex];
            var clientSecret = decodedCredentials[(delimiterIndex + 1)..];

            var client = _clientRepository.Get(clientId);
            if (client is null || !string.Equals(client.ClientSecret, clientSecret, StringComparison.Ordinal))
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