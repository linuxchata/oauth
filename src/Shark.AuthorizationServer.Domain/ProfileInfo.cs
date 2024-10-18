namespace Shark.AuthorizationServer.Domain;

public sealed class ProfileInfo
{
    public string? Subject { get; set; }

    public string? Name { get; set; }

    public string? GivenName { get; set; }

    public string? FamilyName { get; set; }

    public string? Address { get; set; }

    public string? Email { get; set; }

    public bool? EmailVerified { get; set; }

    public string? PhoneNumber { get; set; }

    public bool? PhoneNumberVerified { get; set; }
}