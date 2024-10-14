using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Mappers;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class RegisterApplicationService(
    IStringGeneratorService stringGeneratorService,
    IClientRepository clientRepository,
    IOptions<AuthorizationServerConfiguration> options) : IRegisterApplicationService
{
    private const string ClientSecretBasicAuthMethod = "client_secret_basic";
    private const int DefaultAccessTokenLifetimeInSeconds = 3600;
    private const int DefaultRefreshTokenLifetimeInSeconds = 3600 * 24;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    private readonly HashSet<string> allowedGrandTypes =
    [
        GrantType.AuthorizationCode,
        GrantType.RefreshToken,
        GrantType.Implicit,
        GrantType.ResourceOwnerCredentials,
        GrantType.ClientCredentials
    ];

    public RegisterInternalBaseResponse Read(string clientId)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));

        var client = _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        return client.ToInternalResponse();
    }

    public RegisterInternalBaseResponse Post(RegisterInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = ValidateRequest(request);
        if (response != null)
        {
            return response;
        }

        var client = CreateAndStoreClient(request);

        return client.ToInternalResponse();
    }

    public RegisterInternalBaseResponse Put(string clientId, RegisterUpdateInternalRequest request)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        // Validate client id
        if (string.Equals(clientId, request.ClientId, StringComparison.OrdinalIgnoreCase))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null!;
    }

    public RegisterInternalBaseResponse Delete(string clientId)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));

        var client = _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        _clientRepository.Remove(clientId);

        return new RegisterInternalNoContentResponse();
    }

    private RegisterInternalBadRequestResponse? ValidateRequest(RegisterInternalRequest request)
    {
        // Validate redirect URIs
        if (request.RedirectUris is null || request.RedirectUris.Length == 0)
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
        }

        foreach (var redirectUri in request.RedirectUris)
        {
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
            }
        }

        // Validate token endpoint auth method
        if (!string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod) &&
            !string.Equals(request.TokenEndpointAuthMethod, ClientSecretBasicAuthMethod, StringComparison.OrdinalIgnoreCase))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        // Validate grand types and response types
        if (string.IsNullOrWhiteSpace(request.GrantTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        if (string.IsNullOrWhiteSpace(request.ResponseTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        var grandTypes = request.GrantTypes.Split(' ');
        var responseTypes = request.ResponseTypes.Split(' ');
        foreach (var grandType in grandTypes)
        {
            if (!allowedGrandTypes.Contains(grandType))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }

            if (string.Equals(grandType, GrantType.AuthorizationCode, StringComparison.OrdinalIgnoreCase))
            {
                var codeResponseType = responseTypes.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Code, StringComparison.OrdinalIgnoreCase));

                if (codeResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
            else if (string.Equals(grandType, GrantType.Implicit, StringComparison.OrdinalIgnoreCase))
            {
                var tokenResponseType = responseTypes.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Token, StringComparison.OrdinalIgnoreCase));

                if (tokenResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
        }

        // Validate client name
        if (string.IsNullOrWhiteSpace(request.ClientName))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        // Validate client URI
        if (!string.IsNullOrWhiteSpace(request.ClientUri))
        {
            if (!Uri.IsWellFormedUriString(request.ClientUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }
        }

        // Validate logo URI
        if (!string.IsNullOrWhiteSpace(request.LogoUri))
        {
            if (!Uri.IsWellFormedUriString(request.LogoUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }
        }

        // Validate audience
        if (string.IsNullOrWhiteSpace(request.Audience) ||
            !Uri.IsWellFormedUriString(request.Audience, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private Client CreateAndStoreClient(RegisterInternalRequest request)
    {
        var clientId = Guid.NewGuid().ToString();

        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var registerEndpointUri = new Uri(baseUri, $"{AuthorizationServerEndpoint.Register}/{clientId}");

        var currentDate = DateTime.UtcNow;

        var client = new Client
        {
            ClientName = request.ClientName,
            Enabled = true,
            ClientId = clientId,
            ClientSecret = _stringGeneratorService.GenerateClientSecret(),
            ClientIdIssuedAt = EpochTime.GetIntDate(currentDate),
            ClientSecretExpiresAt = EpochTime.GetIntDate(currentDate.AddYears(1)),
            RedirectUris = request.RedirectUris,
            GrantTypes = request.GrantTypes.Split(' '),
            ResponseTypes = request.ResponseTypes.Split(' '),
            TokenEndpointAuthMethod = ClientSecretBasicAuthMethod,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            Scope = request.Scope.Split(' '),
            Audience = request.Audience,
            AccessTokenLifetimeInSeconds = DefaultAccessTokenLifetimeInSeconds,
            RefreshTokenLifetimeInSeconds = DefaultRefreshTokenLifetimeInSeconds,
            RegistrationAccessToken = _stringGeneratorService.GenerateClientAccessToken(),
            RegistrationClientUri = registerEndpointUri.ToString(),
        };

        _clientRepository.Add(client);

        return client;
    }
}