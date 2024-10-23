using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.Abstractions.Services;
using Shark.AuthorizationServer.Domain;

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

            if (devicePersistedGrant != null && !devicePersistedGrant.IsAuthorized)
            {
                var adjustedDevicePersistedGrant = AdjustDevicePersistedGrant(devicePersistedGrant);

                await _devicePersistedGrantRepository.Remove(devicePersistedGrant);
                await _devicePersistedGrantRepository.Add(adjustedDevicePersistedGrant);
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

    private DevicePersistedGrant AdjustDevicePersistedGrant(DevicePersistedGrant devicePersistedGrant)
    {
        var adjustedDevicePersistedGrant = devicePersistedGrant with { };
        adjustedDevicePersistedGrant.IsAuthorized = true;

        return adjustedDevicePersistedGrant;
    }
}
