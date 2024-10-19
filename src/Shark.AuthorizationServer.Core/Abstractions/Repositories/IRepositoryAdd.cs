namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRepositoryAdd<T>
{
    Task Add(T item);
}
