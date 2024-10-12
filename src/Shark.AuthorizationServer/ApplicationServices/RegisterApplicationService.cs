using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class RegisterApplicationService(
    IStringGeneratorService stringGeneratorService) : IRegisterApplicationService
{
    private const string ClientSecretBasicAuthMethod = "client_secret_basic";

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;

    private readonly HashSet<string> allowedGrandTypes =
    [
        GrantType.AuthorizationCode,
        GrantType.RefreshToken,
        GrantType.Implicit,
        GrantType.ResourceOwnerCredentials,
        GrantType.ClientCredentials
    ];

    public RegisterInternalBaseResponse Execute(RegisterInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = ValidateRequest(request);
        if (response != null)
        {
            return response;
        }

        var currentDate = DateTime.UtcNow;

        return new RegisterInternalResponse
        {
            ClientName = request.ClientName,
            ClientId = Guid.NewGuid().ToString(),
            ClientSecret = _stringGeneratorService.GenerateClientSecret(),
            ClientIdIssuedAt = EpochTime.GetIntDate(currentDate),
            ClientSecretExpiresAt = EpochTime.GetIntDate(currentDate.AddYears(1)),
            RedirectUris = request.RedirectUris,
            GrantTypes = request.GrandTypes.Split(' '),
            TokenEndpointAuthMethod = ClientSecretBasicAuthMethod,
        };
    }

    private RegisterInternalBadRequestResponse? ValidateRequest(RegisterInternalRequest request)
    {
        // Validate redirect URIs
        if (request.RedirectUris is null || request.RedirectUris.Length == 0)
        {
            return new RegisterInternalBadRequestResponse("invalid_redirect_uri");
        }

        foreach (var redirectUri in request.RedirectUris)
        {
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse("invalid_redirect_uri");
            }
        }

        // Validate token endpoint auth method
        if (!string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod) &&
            !string.Equals(request.TokenEndpointAuthMethod, ClientSecretBasicAuthMethod, StringComparison.OrdinalIgnoreCase))
        {
            return new RegisterInternalBadRequestResponse("invalid_client_metadata");
        }

        // Validate grand types and response types
        if (string.IsNullOrWhiteSpace(request.GrandTypes))
        {
            return new RegisterInternalBadRequestResponse("invalid_client_metadata");
        }

        if (string.IsNullOrWhiteSpace(request.ResponseTypes))
        {
            return new RegisterInternalBadRequestResponse("invalid_client_metadata");
        }

        var grandTypes = request.GrandTypes.Split(' ');
        var responseTypes = request.ResponseTypes.Split(' ');
        foreach (var grandType in grandTypes)
        {
            if (!allowedGrandTypes.Contains(grandType))
            {
                return new RegisterInternalBadRequestResponse("invalid_client_metadata");
            }

            if (string.Equals(grandType, GrantType.AuthorizationCode, StringComparison.OrdinalIgnoreCase))
            {
                var codeResponseType = responseTypes.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Code, StringComparison.OrdinalIgnoreCase));

                if (codeResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse("invalid_client_metadata");
                }
            }
            else if (string.Equals(grandType, GrantType.Implicit, StringComparison.OrdinalIgnoreCase))
            {
                var tokenResponseType = responseTypes.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Token, StringComparison.OrdinalIgnoreCase));

                if (tokenResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse("invalid_client_metadata");
                }
            }
        }

        // Validate client name
        if (string.IsNullOrWhiteSpace(request.ClientName))
        {
            return new RegisterInternalBadRequestResponse("invalid_client_metadata");
        }

        // Validate client URI
        if (!string.IsNullOrWhiteSpace(request.ClientUri))
        {
            if (!Uri.IsWellFormedUriString(request.ClientUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse("invalid_client_metadata");
            }
        }

        // Validate logo URI
        if (string.IsNullOrWhiteSpace(request.LogoUri))
        {
            if (!Uri.IsWellFormedUriString(request.LogoUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse("invalid_client_metadata");
            }
        }

        return null;
    }
}