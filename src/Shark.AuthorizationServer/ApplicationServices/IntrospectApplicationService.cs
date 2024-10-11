using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class IntrospectApplicationService : IIntrospectApplicationService
{
    public IntrospectInternalBaseResponse Execute(IntrospectInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(request.Token))
            {
                return new IntrospectInternalResponse { Active = false };
            }

            var jwtToken = handler.ReadJwtToken(request.Token);

            var claims = jwtToken.Claims;

            var username = claims.FirstOrDefault(c => c.Type == ClaimType.Name);
            var subject = claims.FirstOrDefault(c => c.Type == ClaimType.Subject);
            var scope = claims.FirstOrDefault(c => c.Type == ClaimType.Scope);

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