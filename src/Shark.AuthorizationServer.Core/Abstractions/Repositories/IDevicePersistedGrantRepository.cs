using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IDevicePersistedGrantRepository
{
    Task<DevicePersistedGrant?> GetByUserCode(string? userCode);

    Task<DevicePersistedGrant?> GetByDeviceCode(string? deviceCode);

    Task Add(DevicePersistedGrant item);

    Task Update(DevicePersistedGrant item, bool isAuthorized);

    Task Remove(DevicePersistedGrant item);
}
