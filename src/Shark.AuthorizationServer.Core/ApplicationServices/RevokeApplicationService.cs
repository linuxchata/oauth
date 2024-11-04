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
                return new RevokeInternalBadRequestResponse();
            }
        }

        if (!await TryRevokeAccessToken(request.Token))
        {
            await TryRemoveRefreshToken(request.Token);
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

        if (!string.IsNullOrWhiteSpace(jwtToken.Id))
        {
            var revokedToken = await _revokeTokenRepository.Get(jwtToken.Id);
            if (revokedToken is null)
            {
                await _revokeTokenRepository.Add(new RevokeToken(jwtToken.Id, DateTime.UtcNow));
                _logger.LogInformation(
                    "Access token [{Token}] has been added to revocation list. Access token is revoked",
                    token);
            }
            else
            {
                _logger.LogInformation(
                    "Access token [{Token}] has already been revoked",
                    token);
            }

            return true;
        }
        else
        {
            _logger.LogWarning(
                "Access token [{Token}] does not have identfier. Access token cannot be revoked",
                token);
            //// If token was read, so it is a access token. Marked it as handled
            return true;
        }
    }

    private async Task TryRemoveRefreshToken(string token)
    {
        var refreshToken = await _persistedGrantRepository.Get(token);
        if (refreshToken is not null)
        {
            await _persistedGrantRepository.Remove(token);
            //// Do not log refresh token value
            _logger.LogInformation("Refresh token has been removed");
        }
    }
}