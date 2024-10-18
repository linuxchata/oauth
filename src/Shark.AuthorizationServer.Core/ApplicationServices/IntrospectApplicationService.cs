using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Introspect;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class IntrospectApplicationService(
    IRevokeTokenRepository revokeTokenStore,
    ILogger<IntrospectApplicationService> logger) : IIntrospectApplicationService
{
    private readonly IRevokeTokenRepository _revokeTokenStore = revokeTokenStore;
    private readonly ILogger<IntrospectApplicationService> _logger = logger;

    public IntrospectInternalBaseResponse Execute(IntrospectInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        try
        {
            // Try to read token
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(request.Token))
            {
                _logger.LogWarning("Token is not a valid access token");
                return new IntrospectInternalResponse { Active = false };
            }

            var jwtToken = handler.ReadJwtToken(request.Token);

            // Check revokation list
            if (!string.IsNullOrWhiteSpace(jwtToken.Id))
            {
                var revokedToken = _revokeTokenStore.Get(jwtToken.Id);
                if (revokedToken is not null)
                {
                    _logger.LogInformation("Access token has been revoked");
                    return new IntrospectInternalResponse { Active = false };
                }
            }

            // Create response
            var claims = jwtToken.Claims;

            var username = claims.FirstOrDefault(c => c.Type == ClaimType.Name);
            var subject = claims.FirstOrDefault(c => c.Type == ClaimType.Subject);
            var scope = claims.FirstOrDefault(c => c.Type == ClaimType.Scope);

            //// TODO: Check ValidTo and ValidFrom dates

            return new IntrospectInternalResponse
            {
                Active = true,
                Scope = scope?.Value,
                Username = username?.Value,
                TokenType = AccessTokenType.Bearer,
                Expire = EpochTime.GetIntDate(jwtToken.ValidTo),
                IssuedAt = EpochTime.GetIntDate(jwtToken.IssuedAt),
                NotBefore = EpochTime.GetIntDate(jwtToken.ValidFrom),
                Subject = subject?.Value,
                Audience = string.Join(" ", jwtToken.Audiences),
                Issuer = jwtToken.Issuer,
                JwTId = jwtToken.Id,
            };
        }
        catch (Exception)
        {
            return new IntrospectInternalResponse { Active = false };
        }
    }
}