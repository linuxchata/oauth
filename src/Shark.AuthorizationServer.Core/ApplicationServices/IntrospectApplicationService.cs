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
    IRevokeTokenRepository revokeTokenRepository,
    ILogger<IntrospectApplicationService> logger) : IIntrospectApplicationService
{
    private readonly IRevokeTokenRepository _revokeTokenRepository = revokeTokenRepository;
    private readonly ILogger<IntrospectApplicationService> _logger = logger;

    public async Task<IntrospectInternalBaseResponse> Execute(IntrospectInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        try
        {
            var jwtToken = TryReadToken(request);
            if (jwtToken is null)
            {
                return new IntrospectInternalResponse { Active = false };
            }

            var response = await CheckRevokationList(jwtToken);
            if (response != null)
            {
                return response;
            }

            return CreateResponse(jwtToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{message}", ex.Message);
            return new IntrospectInternalResponse { Active = false };
        }
    }

    private JwtSecurityToken? TryReadToken(IntrospectInternalRequest request)
    {
        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(request.Token))
        {
            _logger.LogWarning("Token is not a valid access token");
            return null;
        }

        return handler.ReadJwtToken(request.Token);
    }

    private async Task<IntrospectInternalResponse?> CheckRevokationList(JwtSecurityToken jwtToken)
    {
        if (!string.IsNullOrWhiteSpace(jwtToken.Id))
        {
            var revokedToken = await _revokeTokenRepository.Get(jwtToken.Id);
            if (revokedToken is not null)
            {
                _logger.LogInformation("Access token with identifier {jwtTokenId} has been revoked", jwtToken.Id);
                return new IntrospectInternalResponse { Active = false };
            }
        }

        return null;
    }

    private IntrospectInternalResponse CreateResponse(JwtSecurityToken jwtToken)
    {
        var claims = jwtToken.Claims;

        var username = claims.FirstOrDefault(c => c.Type == ClaimType.Name);
        var subject = claims.FirstOrDefault(c => c.Type == ClaimType.Subject);
        var scope = claims.FirstOrDefault(c => c.Type == ClaimType.Scope);

        // TODO: Check ValidTo and ValidFrom dates

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
            JwtId = jwtToken.Id,
        };
    }
}