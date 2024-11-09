using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
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

    /// <summary>
    /// Handle authentication with client's identified and client's secret.
    /// </summary>
    /// <returns>Authenticate result.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorizationHeaderValue = GetAndValidateAuthorizationHeader();
        if (string.IsNullOrWhiteSpace(authorizationHeaderValue))
        {
            var policy = Context.GetEndpoint()?.Metadata.GetMetadata<AuthorizeAttribute>()?.Policy;
            if (policy != null && !policy.EqualsTo(Policy.Strict))
            {
                // Revert statement - authenticate the client if client authentication is included (RFC 6749)
                return AuthenticateResult.Success(CreateAuthenticationTicket());
            }
            else
            {
                return AuthenticateResult.Fail(UnauthorizedMessage);
            }
        }

        var (clientId, clientSecret) = GetCredentials(authorizationHeaderValue);

        if (!await ValidateCredentials(clientId, clientSecret))
        {
            return AuthenticateResult.Fail(UnauthorizedMessage);
        }

        return AuthenticateResult.Success(CreateAuthenticationTicket(clientId!));
    }

    private string? GetAndValidateAuthorizationHeader()
    {
        var authorizationHeaderValue = Request.Headers?.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorizationHeaderValue))
        {
            return null;
        }

        if (!authorizationHeaderValue.StartsWith(Common.Constants.Scheme.Basic + ' ', StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return authorizationHeaderValue;
    }

    private static (string? ClientId, string? ClientSecret) GetCredentials(string authorizationHeaderValue)
    {
        try
        {
            var credentials = authorizationHeaderValue[Common.Constants.Scheme.Basic.Length..].Trim();

            var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(credentials));

            var delimiterIndex = decodedCredentials.IndexOf(":", StringComparison.OrdinalIgnoreCase);
            if (delimiterIndex == -1)
            {
                return (null, null);
            }

            var clientId = decodedCredentials[..delimiterIndex];
            var clientSecret = decodedCredentials[(delimiterIndex + 1)..];

            return (clientId, clientSecret);
        }
        catch (FormatException)
        {
            return (null, null);
        }
    }

    private async Task<bool> ValidateCredentials(string? clientId, string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return false;
        }

        var client = await _clientRepository.Get(clientId);
        if (client == null || !client.ClientSecret.EqualsTo(clientSecret))
        {
            return false;
        }

        return true;
    }

    private AuthenticationTicket CreateAuthenticationTicket(string? clientId = null)
    {
        var claims = new List<Claim>();

        if (!string.IsNullOrWhiteSpace(clientId))
        {
            claims.Add(new(ClaimType.ClientId, clientId));
        }

        var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
        return new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), Scheme.Name);
    }
}