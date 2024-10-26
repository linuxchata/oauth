using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Validators;

public interface IDeviceAuthorizationValidator
{
    DeviceAuthorizationBadRequestResponse? ValidateRequest(DeviceAuthorizationInternalRequest request, Client? client);
}