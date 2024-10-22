using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Revoke;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class RevokeApplicationService(
    IPersistedGrantRepository persistedGrantRepository,
    IRevokeTokenRepository revokeTokenRepository,
    ILogger<TokenApplicationService> logger) : IRevokeApplicationService
{
    private readonly IPersistedGrantRepository _persistedGrantRepository = persistedGrantRepository;
    private readonly IRevokeTokenRepository _revokeTokenRepository = revokeTokenRepository;
    private readonly ILogger<TokenApplicationService> _logger = logger;

    public async Task<RevokeInternalBaseResponse> Execute(RevokeInternalRequest request)
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
            var revokedToken = await _revokeTokenRepository.Get(jwtToken.Id);
            if (revokedToken is null)
            {
                await _revokeTokenRepository.Add(new RevokeToken(jwtToken.Id, DateTime.UtcNow));
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