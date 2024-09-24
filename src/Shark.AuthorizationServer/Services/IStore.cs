namespace Shark.AuthorizationServer.Services;

public interface IStore<T>
{
    T? Get(string? value);

    void Add(T item);
}
