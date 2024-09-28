namespace Shark.Sample.Client.ApplicationServices;

public interface ICallBackApplicationService
{
    Task Execute(string code, string scope, string? state);
}
