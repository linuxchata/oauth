using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class DeviceAuthorizeApplicationService(
    IStringGeneratorService stringGeneratorService,
    IClientRepository clientRepository,
    ILogger<DeviceAuthorizeApplicationService> logger) : IDeviceAuthorizationApplicationService
{
    // The minimum amount of time in seconds that the client
    // should wait between polling requests to the token endpoint.
    private const int IntervalInSeconds = 5;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly ILogger<DeviceAuthorizeApplicationService> _logger = logger;

    public async Task<DeviceAuthorizationBaseResponse> Execute(DeviceAuthorizationInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var client = await _clientRepository.Get(request.ClientId);

        var response = ValidateClient(client, request);
        if (response != null)
        {
            return response;
        }

        var result = new DeviceAuthorizationResponse
        {
            DeviceCode = _stringGeneratorService.GenerateDeviceCode(),
            UserCode = _stringGeneratorService.GenerateUserDeviceCode(),
            VerificationUri = string.Empty,
            VerificationUriComplete = string.Empty,
            ExpiresIn = 0,
            Interval = IntervalInSeconds,
        };

        return result;
    }

    private DeviceAuthorizationBadRequestResponse? ValidateClient(
        Client? client,
        DeviceAuthorizationInternalRequest request)
    {
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{clientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidClient);
        }

        if (!string.Equals(request.ClientSecret, client.ClientSecret, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Invalid client secret for the client [{clientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidClient);
        }

        if (!client.GrantTypes.ToHashSet().Contains(GrantType.DeviceCode))
        {
            _logger.LogWarning("Invalid grant for the client [{clientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }
}