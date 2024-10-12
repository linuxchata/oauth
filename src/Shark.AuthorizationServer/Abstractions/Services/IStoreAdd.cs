namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IStoreAdd<T>
{
    void Add(T item);
}
