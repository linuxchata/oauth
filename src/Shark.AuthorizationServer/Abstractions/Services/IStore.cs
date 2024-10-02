namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IStore<T>
{
    T? Get(string? value);

    void Add(T item);

    void Remove(string? value);
}
