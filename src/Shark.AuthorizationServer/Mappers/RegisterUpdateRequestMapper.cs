using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class RegisterUpdateRequestMapper
{
    public static RegisterUpdateInternalRequest ToInternalRequest(this RegisterUpdateRequest request)
    {
        return new RegisterUpdateInternalRequest
        {
            ClientName = request.client_name,
            ClientId = request.client_id,
            ClientSecret = request.client_secret,
            RedirectUris = request.redirect_uris,
            GrantTypes = request.grant_types,
            ResponseTypes = request.response_types,
            TokenEndpointAuthMethod = request.token_endpoint_auth_method,
            ClientUri = request.client_uri,
            LogoUri = request.logo_uri,
            Scope = request.scope,
            Audience = request.audience,
        };
    }
}