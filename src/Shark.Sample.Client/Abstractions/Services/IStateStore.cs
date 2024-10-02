namespace Shark.Sample.Client.Abstractions.Services;

public interface IStateStore
{
    string? Get(string key);

    void Add(string key, string state);
}
