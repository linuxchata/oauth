namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface ICallBackService
{
    Task Execute(string? accessToken, string? tokenType, string? code, string? scope, string? state);
}
