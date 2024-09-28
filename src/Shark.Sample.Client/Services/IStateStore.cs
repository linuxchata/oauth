namespace Shark.Sample.Client.Services;

public interface IStateStore
{
    string? Get();

    void Add(string state);
}
