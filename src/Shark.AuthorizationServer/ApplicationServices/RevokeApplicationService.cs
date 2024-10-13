using System.IdentityModel.Tokens.Jwt;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Abstractions.Repositories;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class RevokeApplicationService(
    IPersistedGrantRepository persistedGrantStore,
    IRevokeTokenRepository revokeTokenStore,
    ILogger<TokenApplicationService> logger) : IRevokeApplicationService
{
    private readonly IPersistedGrantRepository _persistedGrantStore = persistedGrantStore;
    private readonly IRevokeTokenRepository _revokeTokenStore = revokeTokenStore;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public RevokeInternalBaseResponse Execute(RevokeInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        if (!string.IsNullOrWhiteSpace(request.TokenHint))
        {
            if (string.Equals(request.TokenHint, TokenHint.AccessToken))
            {
                TryRevokeAccessToken(request.Token);
            }
            else if (string.Equals(request.TokenHint, TokenHint.RefreshToken))
            {
                TryRemoveRefreshToken(request.Token);
            }
            else
            {
                return new RevokeInternalBadRequestResponse();
            }
        }

        if (!TryRevokeAccessToken(request.Token))
        {
            TryRemoveRefreshToken(request.Token);
        }

        return new RevokeInternalResponse();
    }

    private bool TryRevokeAccessToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(token))
        {
            // Do not log token value, since it can be a refresh token
            _logger.LogWarning("Token is not a valid access token");
            return false;
        }

        var jwtToken = handler.ReadJwtToken(token);

        if (!string.IsNullOrWhiteSpace(jwtToken.Id))
        {
            var revokedToken = _revokeTokenStore.Get(jwtToken.Id);
            if (revokedToken is null)
            {
                _revokeTokenStore.Add(new RevokeToken(jwtToken.Id, DateTime.UtcNow));
                _logger.LogInformation(
                    "Access token [{token}] has been added to revocation list. Access token is revoked",
                    token);
            }
            else
            {
                _logger.LogInformation(
                    "Access token [{token}] has already been revoked",
                    token);
            }

            return true;
        }
        else
        {
            _logger.LogWarning(
                "Access token [{token}] does not have identfier. Access token cannot be revoked",
                token);
            //// If token was read, so it is a access token. Marked it as handled
            return true;
        }
    }

    private void TryRemoveRefreshToken(string token)
    {
        var refreshToken = _persistedGrantStore.Get(token);
        if (refreshToken is not null)
        {
            _persistedGrantStore.Remove(token);
            //// Do not log refresh token value
            _logger.LogInformation("Refresh token has been removed");
        }
    }
}