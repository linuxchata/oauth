namespace Shark.AuthorizationServer.Domain.Extensions;

public static class DevicePersistedGrantExtensions
{
    public static bool HasExpired(this DevicePersistedGrant persistedGrant)
    {
        var expirationDate = persistedGrant.CreatedDate.AddSeconds(persistedGrant.ExpiredIn);
        return DateTime.UtcNow > expirationDate;
    }
}