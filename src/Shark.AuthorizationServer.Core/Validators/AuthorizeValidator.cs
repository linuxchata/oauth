using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class AuthorizeValidator(ILogger<AuthorizeValidator> logger) : IAuthorizeValidator
{
    private readonly ILogger<AuthorizeValidator> _logger = logger;

    public AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request, Client? client)
    {
        // Validate client
        if (client == null)
        {
            _logger.LogWarning("Unknown client");
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate response type
        if (!ResponseType.Supported.Contains(request.ResponseType))
        {
            _logger.LogWarning(
                "Unsupported response type [{ResponseType}] by server",
                request.ResponseType.Sanitize());
            return new AuthorizeInternalBadRequestResponse(Error.UnsupportedResponseType);
        }

        if (!client.ResponseTypes.ToHashSet().Contains(request.ResponseType))
        {
            _logger.LogWarning(
                "Unsupported response type [{ResponseType}] by client",
                request.ResponseType.Sanitize());
            return new AuthorizeInternalBadRequestResponse(Error.UnauthorizedClient);
        }

        // Validate redirect URI
        if (!client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URL [{RedirectUri}] for client", request.RedirectUri.Sanitize());
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        // Validate requested scopes against client's allowed scopes
        var allowedClientScopes = client.Scope.ToHashSet();
        var scopes = request.Scopes;
        foreach (var scope in scopes)
        {
            if (!allowedClientScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope [{Scope}] for client", scope.Sanitize());
                return new AuthorizeInternalBadRequestResponse(Error.InvalidScope);
            }
        }

        // Validate code challenge method
        if (!string.IsNullOrWhiteSpace(request.CodeChallengeMethod) &&
            !CodeChallengeMethod.Supported.Contains(request.CodeChallengeMethod))
        {
            _logger.LogWarning(
                "Unsupported code challenge method [{CodeChallengeMethod}] by server",
                request.CodeChallengeMethod.Sanitize());
            return new AuthorizeInternalBadRequestResponse(Error.InvalidRequest);
        }

        return null;
    }
}