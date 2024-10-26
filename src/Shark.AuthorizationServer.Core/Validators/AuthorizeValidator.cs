using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class AuthorizeValidator(
    ILogger<AuthorizeValidator> logger) : IAuthorizeValidator
{
    private readonly ILogger<AuthorizeValidator> _logger = logger;

    public AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request, Client? client)
    {
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{ClientId}]", request.ClientId);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        if (!client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning(
                "Mismatched redirect URL [{RedirectUri}] for client [{ClientId}]",
                request.RedirectUri,
                request.ClientId);
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        var allowedClientScopes = client.Scope.ToHashSet();
        var scopes = request.Scopes;
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning(
                    "Mismatched scope [{Scope}] for client [{ClientId}]",
                    scope,
                    request.ClientId);
                return new AuthorizeInternalBadRequestResponse(Error.InvalidScope);
            }
        }

        return null;
    }
}