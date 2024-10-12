namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IStoreRemove<T>
{
    void Remove(string? value);
}
