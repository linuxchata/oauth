using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Mappers;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;
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

        var response = ValidatePostRequest(request);
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

        var response = ValidateClientId(clientId, request.ClientId);
        if (response != null)
        {
            return response;
        }

        var client = _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        response = ValidateClientSecret(client.ClientSecret, request.ClientSecret);
        if (response != null)
        {
            return response;
        }

        response = ValidatePutRequest(request);
        if (response != null)
        {
            return response;
        }

        var newClient = CreateAndReplaceClient(request, client);

        return newClient.ToInternalResponse();
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

    private RegisterInternalBadRequestResponse? ValidatePostRequest(RegisterInternalRequest request)
    {
        var response = ValidateRedirectUris(request.RedirectUris);
        if (response is not null)
        {
            return response;
        }

        response = ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod);
        if (response is not null)
        {
            return response;
        }

        response = ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes);
        if (response is not null)
        {
            return response;
        }

        response = ValidateClientName(request.ClientName);
        if (response is not null)
        {
            return response;
        }

        response = ValidateClientUri(request.ClientUri);
        if (response is not null)
        {
            return response;
        }

        response = ValidateLogoUri(request.LogoUri);
        if (response is not null)
        {
            return response;
        }

        response = ValidateAudience(request.Audience);
        if (response is not null)
        {
            return response;
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidatePutRequest(RegisterUpdateInternalRequest request)
    {
        var response = ValidateRedirectUris(request.RedirectUris);
        if (response is not null)
        {
            return response;
        }

        response = ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod);
        if (response is not null)
        {
            return response;
        }

        response = ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes);
        if (response is not null)
        {
            return response;
        }

        response = ValidateClientName(request.ClientName);
        if (response is not null)
        {
            return response;
        }

        response = ValidateClientUri(request.ClientUri);
        if (response is not null)
        {
            return response;
        }

        response = ValidateLogoUri(request.LogoUri);
        if (response is not null)
        {
            return response;
        }

        response = ValidateAudience(request.Audience);
        if (response is not null)
        {
            return response;
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientId(string clientId, string requestClientId)
    {
        if (!string.Equals(clientId, requestClientId, StringComparison.OrdinalIgnoreCase))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientSecret(string clientSecret, string? requestClientSecret)
    {
        if (!string.IsNullOrWhiteSpace(requestClientSecret))
        {
            if (!string.Equals(requestClientSecret, clientSecret, StringComparison.OrdinalIgnoreCase))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateRedirectUris(string[] redirectUris)
    {
        if (redirectUris is null || redirectUris.Length == 0)
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
        }

        foreach (var redirectUri in redirectUris)
        {
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
    {
        if (!string.IsNullOrWhiteSpace(tokenEndpointAuthMethod) &&
            !string.Equals(tokenEndpointAuthMethod, ClientSecretBasicAuthMethod, StringComparison.OrdinalIgnoreCase))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateGrandTypesAndResponseTypes(string grantTypes, string responseTypes)
    {
        if (string.IsNullOrWhiteSpace(grantTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        if (string.IsNullOrWhiteSpace(responseTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        var grandTypesArray = grantTypes.Split(' ');
        var responseTypesArray = responseTypes.Split(' ');
        foreach (var grandType in grandTypesArray)
        {
            if (!allowedGrandTypes.Contains(grandType))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }

            if (string.Equals(grandType, GrantType.AuthorizationCode, StringComparison.OrdinalIgnoreCase))
            {
                var codeResponseType = responseTypesArray.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Code, StringComparison.OrdinalIgnoreCase));

                if (codeResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
            else if (string.Equals(grandType, GrantType.Implicit, StringComparison.OrdinalIgnoreCase))
            {
                var tokenResponseType = responseTypesArray.FirstOrDefault(
                    t => string.Equals(t, ResponseType.Token, StringComparison.OrdinalIgnoreCase));

                if (tokenResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientUri(string? clientUri)
    {
        if (!string.IsNullOrWhiteSpace(clientUri))
        {
            if (!Uri.IsWellFormedUriString(clientUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateLogoUri(string? logoUri)
    {
        if (!string.IsNullOrWhiteSpace(logoUri))
        {
            if (!Uri.IsWellFormedUriString(logoUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience) ||
            !Uri.IsWellFormedUriString(audience, UriKind.Absolute))
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

    private Client CreateAndReplaceClient(RegisterUpdateInternalRequest request, Client client)
    {
        var newClient = new Client
        {
            ClientName = request.ClientName,
            Enabled = true,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientIdIssuedAt = client.ClientIdIssuedAt,
            ClientSecretExpiresAt = client.ClientSecretExpiresAt,
            RedirectUris = request.RedirectUris,
            GrantTypes = request.GrantTypes.Split(' '),
            ResponseTypes = request.ResponseTypes.Split(' '),
            TokenEndpointAuthMethod = request.TokenEndpointAuthMethod,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            Scope = request.Scope.Split(' '),
            Audience = request.Audience,
            AccessTokenLifetimeInSeconds = client.AccessTokenLifetimeInSeconds,
            RefreshTokenLifetimeInSeconds = client.RefreshTokenLifetimeInSeconds,
            RegistrationAccessToken = client.RegistrationAccessToken,
            RegistrationClientUri = client.RegistrationClientUri,
        };

        _clientRepository.Remove(client.ClientId);
        _clientRepository.Add(newClient);

        return newClient;
    }
}