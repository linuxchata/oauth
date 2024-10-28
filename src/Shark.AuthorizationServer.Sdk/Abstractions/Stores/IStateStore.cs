namespace Shark.AuthorizationServer.Sdk.Abstractions.Stores;

public interface IStateStore
{
    string? Get(string key);

    void Add(string key, string state);
}
