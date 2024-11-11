using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class AuthorizeValidator(
    ILogger<AuthorizeValidator> logger) : BaseValidator<AuthorizeInternalBadRequestResponse>, IAuthorizeValidator
{
    private readonly ILogger<AuthorizeValidator> _logger = logger;

    public AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request, Client? client)
    {
        return CheckAll(
            ValidateClient(client),
            ValidateResponseType(request, client!),
            ValidateRedirectUri(request, client!),
            ValidateScopes(request, client!),
            ValidateCodeChallengeMethod(request));
    }

    private AuthorizeInternalBadRequestResponse? ValidateClient(Client? client)
    {
        if (client == null)
        {
            _logger.LogWarning("Unknown client");
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        return null;
    }

    private AuthorizeInternalBadRequestResponse? ValidateResponseType(AuthorizeInternalRequest request, Client client)
    {
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

        return null;
    }

    private AuthorizeInternalBadRequestResponse? ValidateRedirectUri(AuthorizeInternalRequest request, Client client)
    {
        if (!client.RedirectUris.Contains(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URL [{RedirectUri}] for client", request.RedirectUri.Sanitize());
            return new AuthorizeInternalBadRequestResponse(Error.InvalidClient);
        }

        return null;
    }

    private AuthorizeInternalBadRequestResponse? ValidateScopes(AuthorizeInternalRequest request, Client client)
    {
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

        return null;
    }

    private AuthorizeInternalBadRequestResponse? ValidateCodeChallengeMethod(AuthorizeInternalRequest request)
    {
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