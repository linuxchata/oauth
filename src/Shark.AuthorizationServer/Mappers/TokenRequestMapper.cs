using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class TokenRequestMapper
{
    public static TokenInternalRequest ToInternalRequest(this TokenRequest request)
    {
        return new TokenInternalRequest
        {
            GrantType = request.grant_type,
            Code = request.code,
            CodeVerifier = request.code_verifier,
            RedirectUri = request.redirect_uri,
            ClientId = request.client_id,
            ClientSecret = request.client_secret,
            Scopes = request.scope?.Split(' ') ?? [],
            RefreshToken = request.refresh_token,
            Username = request.username,
            Password = request.password,
        };
    }
}