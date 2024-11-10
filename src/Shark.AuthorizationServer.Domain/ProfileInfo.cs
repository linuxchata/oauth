namespace Shark.AuthorizationServer.Domain;

public sealed class ProfileInfo
{
    public string? Subject { get; set; }

    public string? Name { get; set; }

    public string? FamilyName { get; set; }

    public string? GivenName { get; set; }

    public string? MiddleName { get; set; }

    public string? Nickname { get; set; }

    public string? PreferredUsername { get; set; }

    public string? Profile { get; set; }

    public string? Picture { get; set; }

    public string? Website { get; set; }

    public string? Gender { get; set; }

    public string? Birthdate { get; set; }

    public string? ZoneInfo { get; set; }

    public string? Locale { get; set; }

    public string? UpdatedAt { get; set; }

    public string? Email { get; set; }

    public bool? EmailVerified { get; set; }

    public string? Address { get; set; }

    public string? PhoneNumber { get; set; }

    public bool? PhoneNumberVerified { get; set; }
}