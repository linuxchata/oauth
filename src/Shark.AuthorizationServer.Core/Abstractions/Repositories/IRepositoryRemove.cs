namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRepositoryRemove<T>
{
    void Remove(string? value);
}
