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

        return devicePersistedGrant != null && !devicePersistedGrant.IsAuthorized.HasValue;
    }

    public async Task Authorize(string? userCode)
    {
        await UpdateDevicePersistedGrant(userCode, true);
    }

    public async Task Deny(string? userCode)
    {
        await UpdateDevicePersistedGrant(userCode, false);
    }

    private async Task UpdateDevicePersistedGrant(string? userCode, bool isAuthorized)
    {
        if (!string.IsNullOrWhiteSpace(userCode))
        {
            var devicePersistedGrant = await _devicePersistedGrantRepository.GetByUserCode(userCode);

            if (devicePersistedGrant != null && !devicePersistedGrant.IsAuthorized.HasValue)
            {
                await _devicePersistedGrantRepository.Update(devicePersistedGrant, isAuthorized);
            }
        }
    }
}
