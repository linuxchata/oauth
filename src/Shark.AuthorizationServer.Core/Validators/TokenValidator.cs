using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

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

    public TokenInternalBadRequestResponse? ValidateCodeGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for {GrantType} persisted grant", GrantType.AuthorizationCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI for {GrantType} persisted grant", GrantType.AuthorizationCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = persistedGrant.Scopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope for {GrantType} persisted grant", GrantType.AuthorizationCode);
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
                _logger.LogWarning("Mismatched code challenge for {GrantType} persisted grant", GrantType.AuthorizationCode);
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        return null;
    }

    public TokenInternalBadRequestResponse? ValidateRefreshTokenGrant(
        PersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for {GrantType} persisted grant", GrantType.RefreshToken);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's redirect URI
        if (!persistedGrant.RedirectUri.EqualsTo(request.RedirectUri))
        {
            _logger.LogWarning("Mismatched redirect URI for {GrantType} persisted grant", GrantType.RefreshToken);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }

    public TokenInternalBadRequestResponse? ValidateDeviceCodeGrant(
        DevicePersistedGrant? persistedGrant,
        TokenInternalRequest request)
    {
        // Validate grant
        if (persistedGrant is null)
        {
            _logger.LogWarning("Persistent grant was not found");
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's client
        if (!persistedGrant.ClientId.EqualsTo(request.ClientId))
        {
            _logger.LogWarning("Mismatched client identifier for {GrantType} persisted grant", GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        // Validate grant's scopes
        var allowedScopes = persistedGrant.Scopes.ToHashSet();
        foreach (var scope in request.Scopes)
        {
            if (!allowedScopes.Contains(scope))
            {
                _logger.LogWarning("Mismatched scope for {GrantType} persisted grant", GrantType.DeviceCode);
                return new TokenInternalBadRequestResponse(Error.InvalidGrant);
            }
        }

        // Validate grant's device code
        if (!persistedGrant.DeviceCode.EqualsTo(request.DeviceCode))
        {
            _logger.LogWarning("Mismatched device code for {GrantType} persisted grant", GrantType.DeviceCode);
            return new TokenInternalBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }
}