namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IStoreGet<T>
{
    T? Get(string? value);
}
