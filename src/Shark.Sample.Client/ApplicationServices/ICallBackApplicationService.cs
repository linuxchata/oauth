namespace Shark.Sample.Client.ApplicationServices;

public interface ICallBackApplicationService
{
    Task Execute(string? accessToken, string? tokenType, string? code, string? scope, string? state);
}
