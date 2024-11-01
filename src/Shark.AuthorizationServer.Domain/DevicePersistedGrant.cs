namespace Shark.AuthorizationServer.Domain;

public record DevicePersistedGrant
{
    public required string Type { get; set; }

    public required string ClientId { get; set; }

    public required string[] Scopes { get; set; }

    public required string DeviceCode { get; set; }

    public required string UserCode { get; set; }

    public required bool? IsAuthorized { get; set; }

    public required DateTime CreatedDate { get; set; }

    public int ExpiredIn { get; set; }
}