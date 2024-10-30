namespace Shark.AuthorizationServer.Sdk.Configurations;

public sealed class RetryOnGetConfigurationOptions
{
    public bool Enabled { get; set; } = false;

    public int DelayInSeconds { get; set; } = 1;

    public int MaxAttempts { get; set; } = 3;

    public int TimeoutInSeconds { get; set; } = 3;
}