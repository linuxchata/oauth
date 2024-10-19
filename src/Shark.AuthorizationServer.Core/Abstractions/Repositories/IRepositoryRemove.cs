namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRepositoryRemove<T>
{
    Task Remove(string? value);
}
