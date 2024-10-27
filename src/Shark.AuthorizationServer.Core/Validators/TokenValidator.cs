using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class TokenValidator(
    ILogger<TokenValidator> logger) : ITokenValidator
{
    private readonly ILogger<TokenValidator> _logger = logger;

    public TokenInternalBadRequestResponse? ValidateRequest(
        TokenInternalRequest request,
        Client? client,
        ClaimsPrincipal claimsPrincipal)
    {
        // Validate client
        if (client is null)
        {
            _logger.LogWarning("Unknown client");
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate client secret
        if ((!claimsPrincipal.Identity?.IsAuthenticated ?? true) &&
            !client.ClientSecret.EqualsTo(request.ClientSecret))
        {
            _logger.LogWarning("Invalid client secret");
            return new TokenInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate redirect URI
        if (!string.IsNullOrWhiteSpace(request.RedirectUri) &&
            !client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URL [{RedirectUri}]", request.RedirectUri);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate requested scopes against client's allowed scopes
        var allowedClientScopes = client.Scope.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope [{Scope}]", scope);
                return new TokenInternalBadRequestResponse(Error.InvalidScope);
            }
        }

        return null;
    }
}