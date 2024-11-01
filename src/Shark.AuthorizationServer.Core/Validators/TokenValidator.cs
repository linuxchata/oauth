using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Domain.Extensions;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class TokenValidator(
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    ILogger<TokenValidator> logger) : ITokenValidator
{
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
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

        // Validate grant type
        if (string.IsNullOrWhiteSpace(request.GrantType) ||
            !GrantType.Allowed.Contains(request.GrantType))
        {
            _logger.LogWarning("Unsupported grant type {GrantType}", request.GrantType);
            return new TokenInternalBadRequestResponse(Error.UnsupportedGrantType);
        }

        if (!client.GrantTypes.ToHashSet().Contains(request.GrantType))
        {
            _logger.LogWarning("Invalid grant for client");
            return new TokenInternalBadRequestResponse(Error.UnauthorizedClient);
        }

        // Validate client secret
        if ((!claimsPrincipal.Identity?.IsAuthenticated ?? true) &&
            !client.ClientSecret.EqualsTo(request.ClientSecret))
        {
            _logger.LogWarning("Invalid client secret");
            return new TokenInternalBadRequestResponse(Error.UnauthorizedClient);
        }

        // Validate that Confidential client is authenticated
        // <cref="BasicAuthenticationHandler" includes clientid claim when it is available
        if (client.ClientType == Domain.Enumerations.ClientType.Confidential &&
            (claimsPrincipal.Identity?.IsAuthenticated ?? true) &&
            !claimsPrincipal.Claims.Any(c => c.Type.EqualsTo(ClaimType.ClientId)))
        {
            _logger.LogWarning("Invalid client authentication for confidential client");
            return new TokenInternalBadRequestResponse(Error.UnauthorizedClient);
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

    public TokenInternalBadRequestResponse? ValidateCodeGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        using var loggerScope = _logger.BeginScope("[{GrantType}]", GrantType.AuthorizationCode);

        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = persistedGrant.Scopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate grant's code verifier
        if (!string.IsNullOrWhiteSpace(persistedGrant.CodeChallenge))
        {
            if (string.IsNullOrWhiteSpace(request.CodeVerifier))
            {
                _logger.LogWarning("Code verifier was not found in request");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }

            string codeChallenge;

            if (persistedGrant.CodeChallengeMethod.EqualsTo(CodeChallengeMethod.Plain))
            {
                codeChallenge = request.CodeVerifier;
            }
            else if (persistedGrant.CodeChallengeMethod.EqualsTo(CodeChallengeMethod.Sha256))
            {
                codeChallenge = _proofKeyForCodeExchangeService.GetCodeChallenge(
                    request.CodeVerifier,
                    persistedGrant.CodeChallengeMethod!);
            }
            else
            {
                return new TokenInternalBadRequestResponse(Error.InvalidRequest);
            }

            if (!persistedGrant.CodeChallenge.EqualsTo(codeChallenge))
            {
                _logger.LogWarning("Mismatched code challenge");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate expiration
        if (persistedGrant.HasExpired())
        {
            _logger.LogWarning("Persisted grant has expired");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    public TokenInternalBadRequestResponse? ValidateRefreshTokenGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        using var loggerScope = _logger.BeginScope("[{GrantType}]", GrantType.RefreshToken);

        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate expiration
        if (persistedGrant.HasExpired())
        {
            _logger.LogWarning("Persisted grant has expired");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    public TokenInternalBadRequestResponse? ValidateDeviceCodeGrant(
        DevicePersistedGrant? devicePersistedGrant,
        TokenInternalRequest request)
    {
        using var loggerScope = _logger.BeginScope("[{GrantType}]", GrantType.DeviceCode);

        // Validate grant
        if (devicePersistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!devicePersistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = devicePersistedGrant.Scopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope");
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate grant's device code
        if (!devicePersistedGrant.DeviceCode.EqualsTo(request.DeviceCode))
        {
            _logger.LogWarning("Mismatched device code");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate expiration
        if (devicePersistedGrant.HasExpired())
        {
            _logger.LogWarning("Persisted grant has expired");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate whether grant was authorized
        if (!devicePersistedGrant.IsAuthorized.HasValue)
        {
            _logger.LogWarning("The authorization request is still pending");
            return new TokenInternalBadRequestResponse(Error.AuthorizationPending);
        }

        if (devicePersistedGrant.IsAuthorized.HasValue &&
            !devicePersistedGrant.IsAuthorized.Value)
        {
            _logger.LogWarning("The authorization request was denied");
            return new TokenInternalBadRequestResponse(Error.AccessDenied);
        }

        return null;
    }
}