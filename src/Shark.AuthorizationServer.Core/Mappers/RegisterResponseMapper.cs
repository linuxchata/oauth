﻿using Shark.AuthorizationServer.Core.Responses.Register;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Mappers;

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