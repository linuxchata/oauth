using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Mappers;

public static class RegisterResponseMapper
{
    public static RegisterInternalResponse ToInternalResponse(this Client client)
    {
        return new RegisterInternalResponse
        {
            ClientName = client.ClientName,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientIdIssuedAt = client.ClientIdIssuedAt,
            ClientSecretExpiresAt = client.ClientSecretExpiresAt,
            RedirectUris = client.RedirectUris,
            GrantTypes = client.GrantTypes,
            TokenEndpointAuthMethod = client.TokenEndpointAuthMethod,
            RegistrationAccessToken = client.RegistrationAccessToken,
            RegistrationClientUri = client.RegistrationClientUri,
        };
    }
}