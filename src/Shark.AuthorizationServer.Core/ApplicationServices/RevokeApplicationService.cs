using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Revoke;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class RevokeApplicationService(
    ICustomAccessTokenHandler customAccessTokenHandler,
    IPersistedGrantRepository persistedGrantRepository,
    IRevokeTokenRepository revokeTokenRepository,
    ILogger<TokenApplicationService> logger) : IRevokeApplicationService
{
    private readonly ICustomAccessTokenHandler _customAccessTokenHandler = customAccessTokenHandler;
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly IRevokeTokenRepository _revokeTokenRepository = revokeTokenRepository;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public async Task<IRevokeInternalResponse> Execute(RevokeInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        if (!string.IsNullOrWhiteSpace(request.TokenHint))
        {
            if (request.TokenHint.EqualsTo(TokenHint.AccessToken))
            {
                await TryRevokeAccessToken(request.Token);
            }
            else if (request.TokenHint.EqualsTo(TokenHint.RefreshToken))
            {
                await TryRemoveRefreshToken(request.Token);
            }
            else
            {
                // An invalid token type hint value is ignored by the authorization
                // server and does not influence the revocation response (RFC 7009).
                return new RevokeInternalResponse();
            }
        }
        else
        {
            if (!await TryRevokeAccessToken(request.Token))
            {
                await TryRemoveRefreshToken(request.Token);
            }
        }

        return new RevokeInternalResponse();
    }

    private async Task<bool> TryRevokeAccessToken(string token)
    {
        var jwtToken = _customAccessTokenHandler.Read(token, null);
        if (jwtToken is null)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(jwtToken.Id))
        {
            _logger.LogWarning(
                "Access token [{Token}] does not have identfier. Access token cannot be revoked",
                token);

            // If token was read, so it is an access token. Marked it as handled
            return true;
        }

        var revokedToken = await _revokeTokenRepository.Get(jwtToken.Id);
        if (revokedToken is null)
        {
            await _revokeTokenRepository.Add(new RevokeToken(jwtToken.Id, DateTime.UtcNow));
            _logger.LogInformation(
                "Access token with identifier {Id} has been added to revocation list. Access token is revoked",
                jwtToken.Id);

            var persistedGrant = await _persistedGrantRepository.GetByAccessTokenId(jwtToken.Id);
            await TryRemoveRefreshToken(persistedGrant);
        }
        else
        {
            _logger.LogInformation(
                "Access token with identifier {Id} has already been revoked",
                jwtToken.Id);
        }

        return true;
    }

    private async Task TryRemoveRefreshToken(string token)
    {
        var persistedGrant = await _persistedGrantRepository.GetByValue(token);
        if (persistedGrant is not null)
        {
            await TryRemoveRefreshToken(persistedGrant);
        }
    }

    private async Task TryRemoveRefreshToken(PersistedGrant? persistedGrant)
    {
        if (persistedGrant is not null)
        {
            await _persistedGrantRepository.Remove(persistedGrant);
            _logger.LogInformation("Refresh token has been removed (revoked)");
        }
    }
}