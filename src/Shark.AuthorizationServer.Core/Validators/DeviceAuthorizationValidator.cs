using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Validators;
public sealed class DeviceAuthorizationValidator(
    ILogger<DeviceAuthorizationValidator> logger) : IDeviceAuthorizationValidator
{
    private readonly ILogger<DeviceAuthorizationValidator> _logger = logger;

    public DeviceAuthorizationBadRequestResponse? ValidateRequest(DeviceAuthorizationInternalRequest request, Client? client)
    {
        if (client is null)
        {
            _logger.LogWarning("Unknown client with identifier [{ClientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidClient);
        }

        if (!request.ClientSecret.EqualsTo(client.ClientSecret))
        {
            _logger.LogWarning("Invalid client secret for client [{ClientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidClient);
        }

        if (!client.GrantTypes.ToHashSet().Contains(GrantType.DeviceCode))
        {
            _logger.LogWarning("Invalid grant for client [{ClientId}]", request.ClientId);
            return new DeviceAuthorizationBadRequestResponse(Error.InvalidGrant);
        }

        return null;
    }
}