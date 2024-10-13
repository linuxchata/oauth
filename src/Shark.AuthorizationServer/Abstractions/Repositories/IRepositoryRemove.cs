namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IRepositoryRemove<T>
{
    void Remove(string? value);
}
