namespace Shark.AuthorizationServer.Abstractions.Repositories;

public interface IRepositoryGet<T>
{
    T? Get(string? value);
}
