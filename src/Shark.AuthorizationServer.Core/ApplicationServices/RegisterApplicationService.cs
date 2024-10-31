using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Mappers;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class RegisterApplicationService(
    IRegisterValidator registerValidator,
    IStringGeneratorService stringGeneratorService,
    IClientRepository clientRepository,
    IOptions<AuthorizationServerConfiguration> options) : IRegisterApplicationService
{
    private const int DefaultAccessTokenLifetimeInSeconds = 3600;
    private const int DefaultRefreshTokenLifetimeInSeconds = 3600 * 24;

    private readonly IRegisterValidator _registerValidator = registerValidator;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public async Task<IRegisterInternalResponse> ExecuteRead(string clientId)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));

        var client = await _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        return client.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> ExecutePost(RegisterInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = _registerValidator.ValidatePostRequest(request);
        if (response != null)
        {
            return response;
        }

        var client = await CreateAndStoreClient(request);

        return client.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> ExecutePut(string clientId, RegisterUpdateInternalRequest request)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(clientId, nameof(clientId));
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var response = _registerValidator.ValidateClientId(clientId, request.ClientId);
        if (response != null)
        {
            return response;
        }

        var client = await _clientRepository.Get(clientId);
        if (client is null)
        {
            return new RegisterInternalNotFoundResponse();
        }

        response = _registerValidator.ValidateClientSecret(client.ClientSecret, request.ClientSecret);
        if (response != null)
        {
            return response;
        }

        response = _registerValidator.ValidatePutRequest(request);
        if (response != null)
        {
            return response;
        }

        var newClient = await CreateAndReplaceClient(request, client);

        return newClient.ToInternalResponse();
    }

    public async Task<IRegisterInternalResponse> ExecuteDelete(string clientId)
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
            ClientType = Domain.Enumerations.ClientType.Public,
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
            ClientType = client.ClientType,
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