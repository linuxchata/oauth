namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface ICallBackClientService
{
    Task Execute(string? accessToken, string? tokenType, string? code, string? scope, string? state);
}
