namespace Shark.Sample.Client.Services;

public sealed class StateStore : IStateStore
{
    private string? storedState;

    public string? Get()
    {
        return storedState;
    }

    public void Add(string state)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(state);

        storedState = state;
    }
}
