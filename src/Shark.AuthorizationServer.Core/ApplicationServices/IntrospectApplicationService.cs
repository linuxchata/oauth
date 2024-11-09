using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Introspect;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class IntrospectApplicationService(
    ICustomAccessTokenHandler customAccessTokenHandler,
    IRevokeTokenRepository revokeTokenRepository,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<IntrospectApplicationService> logger) : IIntrospectApplicationService
{
    private readonly ICustomAccessTokenHandler _customAccessTokenHandler = customAccessTokenHandler;
    private readonly IRevokeTokenRepository _revokeTokenRepository = revokeTokenRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<IntrospectApplicationService> _logger = logger;

    public async Task<IIntrospectInternalResponse> Execute(
        IntrospectInternalRequest request,
        ClaimsPrincipal clientIdentity)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var clientId = clientIdentity.Claims.FirstOrDefault(c => c.Type.EqualsTo(ClaimType.ClientId))?.Value;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            // BasicAuthenticationHandler must always include clientid claim
            throw new InvalidOperationException("Client identifier can not be found");
        }

        var jwtToken = ReadToken(request.Token);
        if (jwtToken is null)
        {
            return new IntrospectInternalResponse { Active = false };
        }

        var response = await CheckRevokationList(jwtToken);
        if (response != null)
        {
            return response;
        }

        return CreateResponse(jwtToken, clientId);
    }

    private JwtSecurityToken? ReadToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
        };

        return _customAccessTokenHandler.Read(token, tokenValidationParameters);
    }

    private async Task<IntrospectInternalResponse?> CheckRevokationList(JwtSecurityToken jwtToken)
    {
        if (!string.IsNullOrWhiteSpace(jwtToken.Id))
        {
            var revokedToken = await _revokeTokenRepository.Get(jwtToken.Id);
            if (revokedToken is not null)
            {
                _logger.LogInformation("Access token with identifier {JwtTokenId} has been revoked", jwtToken.Id);
                return new IntrospectInternalResponse { Active = false };
            }
        }
        else
        {
            throw new InvalidOperationException("Access token with identifier must be set");
        }

        return null;
    }

    private IntrospectInternalResponse CreateResponse(JwtSecurityToken jwtToken, string clientId)
    {
        var claims = jwtToken.Claims;

        var username = claims.FirstOrDefault(c => c.Type.EqualsTo(ClaimType.Name));
        var subject = claims.FirstOrDefault(c => c.Type.EqualsTo(ClaimType.Subject));
        var scope = claims.FirstOrDefault(c => c.Type.EqualsTo(ClaimType.Scope));

        return new IntrospectInternalResponse
        {
            Active = true,
            Scope = scope?.Value,
            ClientId = clientId,
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