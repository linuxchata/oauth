using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Extensions;
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
    private const int DefaultAccessTokenLifetimeInSeconds = 3600;
    private const int DefaultRefreshTokenLifetimeInSeconds = 3600 * 24;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public async Task<IRegisterInternalResponse> Read(string clientId)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));

        var client = await _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        return client.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> Post(RegisterInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = ValidatePostRequest(request);
        if (response != null)
        {
            return response;
        }

        var client = await CreateAndStoreClient(request);

        return client.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> Put(string clientId, RegisterUpdateInternalRequest request)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = ValidateClientId(clientId, request.ClientId);
        if (response != null)
        {
            return response;
        }

        var client = await _clientRepository.Get(clientId);
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

        var newClient = await CreateAndReplaceClient(request, client);

        return newClient.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> Delete(string clientId)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));

        var client = _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        await _clientRepository.Remove(clientId);

        return new RegisterInternalNoContentResponse();
    }

    private static RegisterInternalBadRequestResponse? ValidatePostRequest(RegisterInternalRequest request)
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

    private static RegisterInternalBadRequestResponse? ValidatePutRequest(RegisterUpdateInternalRequest request)
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

    private static RegisterInternalBadRequestResponse? ValidateClientId(string clientId, string requestClientId)
    {
        if (!clientId.EqualsTo(requestClientId))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateClientSecret(string clientSecret, string? requestClientSecret)
    {
        if (!string.IsNullOrWhiteSpace(requestClientSecret) &&
            !requestClientSecret.EqualsTo(clientSecret))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateRedirectUris(string[] redirectUris)
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

    private static RegisterInternalBadRequestResponse? ValidateTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
    {
        if (!string.IsNullOrWhiteSpace(tokenEndpointAuthMethod) &&
            !tokenEndpointAuthMethod.EqualsTo(ClientAuthMethod.ClientSecretBasic))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateGrandTypesAndResponseTypes(string grantTypes, string responseTypes)
    {
        if (string.IsNullOrWhiteSpace(grantTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        if (string.IsNullOrWhiteSpace(responseTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        var grandTypesList = grantTypes.Split(' ').ToList();
        var responseTypesList = responseTypes.Split(' ').ToList();
        foreach (var grandType in grandTypesList)
        {
            if (!GrantType.AllowedGrandTypes.Contains(grandType))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }

            if (grandType.EqualsTo(GrantType.AuthorizationCode))
            {
                var codeResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Code));

                if (codeResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
            else if (grandType.EqualsTo(GrantType.Implicit))
            {
                var tokenResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Token));

                if (tokenResponseType is null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateClientUri(string? clientUri)
    {
        if (!string.IsNullOrWhiteSpace(clientUri) &&
            !Uri.IsWellFormedUriString(clientUri, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateLogoUri(string? logoUri)
    {
        if (!string.IsNullOrWhiteSpace(logoUri) &&
            !Uri.IsWellFormedUriString(logoUri, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience) ||
            !Uri.IsWellFormedUriString(audience, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private async Task<Client> CreateAndStoreClient(RegisterInternalRequest request)
    {
        var clientId = Guid.NewGuid().ToString();

        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var registerEndpointUri = new Uri(baseUri, $"{AuthorizationServerEndpoint.Registration}/{clientId}");

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
            TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic,
            ClientUri = request.ClientUri,
            LogoUri = request.LogoUri,
            Scope = request.Scope.Split(' '),
            Audience = request.Audience,
            RegistrationAccessToken = _stringGeneratorService.GenerateClientAccessToken(),
            RegistrationClientUri = registerEndpointUri.ToString(),
            AccessTokenLifetimeInSeconds = DefaultAccessTokenLifetimeInSeconds,
            RefreshTokenLifetimeInSeconds = DefaultRefreshTokenLifetimeInSeconds,
        };

        await _clientRepository.Add(client);

        return client;
    }

    private async Task<Client> CreateAndReplaceClient(RegisterUpdateInternalRequest request, Client client)
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

        await _clientRepository.Remove(client.ClientId);
        await _clientRepository.Add(newClient);

        return newClient;
    }
}