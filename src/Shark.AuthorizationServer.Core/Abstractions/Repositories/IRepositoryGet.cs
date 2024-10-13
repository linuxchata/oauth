namespace Shark.AuthorizationServer.Core.Abstractions.Repositories;

public interface IRepositoryGet<T>
{
    T? Get(string? value);
}
