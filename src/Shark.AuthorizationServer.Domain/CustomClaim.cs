namespace Shark.AuthorizationServer.Domain;

public sealed class CustomClaim
{
    public CustomClaim(string type, string value)
    {
        Type = type;
        Value = value;
    }

    public string Type { get; set; }

    public string Value { get; set; }
}