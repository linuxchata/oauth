namespace Shark.Sample.Client.Models;

public sealed class ProtectedResourceConfiguration
{
    public const string Name = nameof(ProtectedResourceConfiguration);

    public required string Endpoint { get; set; }

    public required string Scope { get; set; }
}