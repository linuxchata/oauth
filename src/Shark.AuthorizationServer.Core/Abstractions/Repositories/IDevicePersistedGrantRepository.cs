using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IDevicePersistedGrantRepository
{
    Task<DevicePersistedGrant?> GetByUserCode(string? value);

    Task<DevicePersistedGrant?> GetByDeviceCode(string? value);

    Task Add(DevicePersistedGrant item);

    Task Remove(DevicePersistedGrant item);
}
