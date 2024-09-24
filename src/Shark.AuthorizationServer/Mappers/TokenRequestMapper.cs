using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class TokenRequestMapper
{
    public static TokenInternalRequest ToInternalRequest(this TokenRequest request)
    {
        return new TokenInternalRequest
        {
            ClientId = request.client_id,
            ClientSecret = request.client_secret,
            GrantType = request.grant_type,
            Code = request.code,
            RefreshToken = request.refresh_token,
            RedirectUrl = request.redirect_url,
        };
    }
}