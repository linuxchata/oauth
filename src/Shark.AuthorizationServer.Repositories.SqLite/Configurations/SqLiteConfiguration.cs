namespace Shark.AuthorizationServer.Repositories.SqLite.Configurations;

public sealed class SqLiteConfiguration
{
    public const string Name = "SqLite";

    public required string ConnectionString { get; set; }
}