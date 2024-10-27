namespace Shark.AuthorizationServer.Domain.Extensions;

public static class PersistedGrantExtensions
{
    public static bool HasExpired(this PersistedGrant devicePersistedGrant)
    {
        var expirationDate = devicePersistedGrant.CreatedDate.AddSeconds(devicePersistedGrant.ExpiredIn);
        return DateTime.UtcNow > expirationDate;
    }
}