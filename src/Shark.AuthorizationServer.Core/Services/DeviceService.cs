using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Services;

namespace Shark.AuthorizationServer.Core.Services;

public sealed class DeviceService(IDevicePersistedGrantRepository devicePersistedGrantRepository) : IDeviceService
{
    private readonly IDevicePersistedGrantRepository _devicePersistedGrantRepository = devicePersistedGrantRepository;

    public async Task<bool> ValidateUserCode(string? userCode)
    {
        if (string.IsNullOrWhiteSpace(userCode))
        {
            return false;
        }

        var devicePersistedGrant = await _devicePersistedGrantRepository.GetByUserCode(userCode);

        return devicePersistedGrant != null;
    }

    public async Task Authorize(string? userCode)
    {
        if (!string.IsNullOrWhiteSpace(userCode))
        {
            var devicePersistedGrant = await _devicePersistedGrantRepository.GetByUserCode(userCode);

            if (devicePersistedGrant != null)
            {
                var newDevicePersistedGrant = devicePersistedGrant with { };
                newDevicePersistedGrant.IsAuthorized = true;

                await _devicePersistedGrantRepository.Remove(devicePersistedGrant);
                await _devicePersistedGrantRepository.Add(newDevicePersistedGrant);
            }
        }
    }

    public async Task Deny(string? userCode)
    {
        if (!string.IsNullOrWhiteSpace(userCode))
        {
            var devicePersistedGrant = await _devicePersistedGrantRepository.GetByUserCode(userCode);

            if (devicePersistedGrant != null)
            {
                await _devicePersistedGrantRepository.Remove(devicePersistedGrant);
            }
        }
    }
}
