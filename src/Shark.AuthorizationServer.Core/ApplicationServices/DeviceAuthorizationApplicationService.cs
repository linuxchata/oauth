using System.Web;
using System;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;
using Shark.AuthorizationServer.Common.Extensions;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class DeviceAuthorizationApplicationService(
    IStringGeneratorService stringGeneratorService,
    IClientRepository clientRepository,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<DeviceAuthorizationApplicationService> logger) : IDeviceAuthorizationApplicationService
{
    private const string DevicePath = "device";
    private const string UserCodeQueryParameter = "user_code";
    private const int DefaultDeviceCodeLifetimeInSeconds = 300;

    // The minimum amount of time in seconds that the client
    // should wait between polling requests to the token endpoint.
    private const int IntervalInSeconds = 5;

    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<DeviceAuthorizationApplicationService> _logger = logger;

    public async Task<DeviceAuthorizationBaseResponse> Execute(DeviceAuthorizationInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        var client = await _clientRepository.Get(request.ClientId);

        var response = ValidateClient(client, request);
        if (response != null)
        {
            return response;
        }

        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var userCode = _stringGeneratorService.GenerateUserDeviceCode();

        var result = new DeviceAuthorizationResponse
        {
            DeviceCode = _stringGeneratorService.GenerateDeviceCode(),
            UserCode = userCode,
            VerificationUri = GetVerificationUri(baseUri),
            VerificationUriComplete = GetVerificationCompleteUri(baseUri, userCode),
            ExpiresIn = client!.DeviceCodeLifetimeInSeconds ?? DefaultDeviceCodeLifetimeInSeconds,
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

        if (!request.ClientSecret.EqualsTo(client.ClientSecret))
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

    private string GetVerificationUri(Uri baseUri)
    {
        return (new Uri(baseUri, DevicePath)).ToString();
    }

    private string GetVerificationCompleteUri(Uri baseUri, string userCode)
    {
        var verificationCompleteUri = new Uri(baseUri, DevicePath);

        var verificationCompleteUriBuilder = new UriBuilder(verificationCompleteUri);

        var query = HttpUtility.ParseQueryString(verificationCompleteUriBuilder.Query);
        query[UserCodeQueryParameter] = userCode;
        verificationCompleteUriBuilder.Query = query.ToString();

        return verificationCompleteUriBuilder.ToString();
    }
}