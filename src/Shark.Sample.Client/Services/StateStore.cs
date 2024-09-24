namespace Shark.Sample.Client.Services;

public sealed class StateStore : IStateStore
{
    private string? storedState;

    public string Get()
    {
        if (string.IsNullOrWhiteSpace(storedState))
        {
            throw new Exception("No state stored");
        }

        return storedState;
    }

    public void Add(string state)
    {
        storedState = state;
    }
}
