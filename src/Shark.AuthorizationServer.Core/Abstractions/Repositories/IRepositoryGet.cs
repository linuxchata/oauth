namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRepositoryGet<T>
{
    Task<T?> Get(string? value);
}
