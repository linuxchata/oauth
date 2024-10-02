namespace Shark.Sample.Client.Services;

public interface IStateStore
{
    string? Get(string key);

    void Add(string key, string state);
}
