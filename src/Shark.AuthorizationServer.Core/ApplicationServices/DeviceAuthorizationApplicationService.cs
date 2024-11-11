using System.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class DeviceAuthorizationApplicationService(
    IDeviceAuthorizationValidator deviceAuthorizationValidator,
    IStringGeneratorService stringGeneratorService,
    IClientRepository clientRepository,
    IDevicePersistedGrantRepository devicePersistedGrantRepository,
    IOptions<AuthorizationServerConfiguration> options,
    ILogger<DeviceAuthorizationApplicationService> logger) : IDeviceAuthorizationApplicationService
{
    private const string DevicePath = "device";
    private const string UserCodeQueryParameter = "user_code";
    private const int DefaultDeviceCodeLifetimeInSeconds = 300;

    // The minimum amount of time in seconds that the client
    // should wait between polling requests to the token endpoint.
    private const int IntervalInSeconds = 5;

    private readonly IDeviceAuthorizationValidator _deviceAuthorizationValidator = deviceAuthorizationValidator;
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;
    private readonly IClientRepository _clientRepository = clientRepository;
    private readonly IDevicePersistedGrantRepository _devicePersistedGrantRepository = devicePersistedGrantRepository;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly ILogger<DeviceAuthorizationApplicationService> _logger = logger;

    public async Task<IDeviceAuthorizationResponse> Execute(DeviceAuthorizationInternalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request, nameof(request));

        using var loggerScope = _logger.BeginScope("ClientId:{ClientId}", request.ClientId.Sanitize());

        var client = await _clientRepository.Get(request.ClientId);

        var response = _deviceAuthorizationValidator.ValidateRequest(request, client);
        if (response != null)
        {
            return response;
        }

        return await Handle(request, client!);
    }

    private async Task<DeviceAuthorizationResponse> Handle(DeviceAuthorizationInternalRequest request, Client client)
    {
        _logger.LogInformation("Issuing device code");

        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var deviceCode = _stringGeneratorService.GenerateDeviceCode();
        var userCode = _stringGeneratorService.GenerateUserDeviceCode();
        var expiresIn = client!.DeviceCodeLifetimeInSeconds ?? DefaultDeviceCodeLifetimeInSeconds;

        await StorePersistedGrant(request, deviceCode, userCode, expiresIn);

        return new DeviceAuthorizationResponse
        {
            DeviceCode = deviceCode,
            UserCode = userCode,
            VerificationUri = GetVerificationUri(baseUri),
            VerificationUriComplete = GetVerificationCompleteUri(baseUri, userCode),
            ExpiresIn = expiresIn,
            Interval = IntervalInSeconds,
        };
    }

    private static string GetVerificationUri(Uri baseUri)
    {
        return new Uri(baseUri, DevicePath).ToString();
    }

    private static string GetVerificationCompleteUri(Uri baseUri, string userCode)
    {
        var verificationCompleteUri = new Uri(baseUri, DevicePath);

        var verificationCompleteUriBuilder = new UriBuilder(verificationCompleteUri);

        var query = HttpUtility.ParseQueryString(verificationCompleteUriBuilder.Query);
        query[UserCodeQueryParameter] = userCode;
        verificationCompleteUriBuilder.Query = query.ToString();

        return verificationCompleteUriBuilder.ToString();
    }

    private async Task StorePersistedGrant(
        DeviceAuthorizationInternalRequest request,
        string deviceCode,
        string userCode,
        int expiresIn)
    {
        var devicePersistedGrant = new DevicePersistedGrant
        {
            Type = GrantType.DeviceCode,
            ClientId = request.ClientId,
            Scopes = request.Scopes,
            DeviceCode = deviceCode,
            UserCode = userCode,
            IsAuthorized = null,
            CreatedDate = DateTime.UtcNow,
            ExpiredIn = expiresIn,
        };

        await _devicePersistedGrantRepository.Add(devicePersistedGrant);
    }
}