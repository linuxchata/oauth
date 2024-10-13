using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class RegisterRequestMapper
{
    public static RegisterInternalRequest ToInternalRequest(this RegisterRequest request)
    {
        return new RegisterInternalRequest
        {
            RedirectUris = request.redirect_uris,
            TokenEndpointAuthMethod = request.token_endpoint_auth_method,
            GrandTypes = request.grand_types,
            ResponseTypes = request.response_types,
            ClientName = request.client_name,
            ClientUri = request.client_uri,
            LogoUri = request.logo_uri,
            Scope = request.scope,
            Audience = request.audience,
        };
    }
}