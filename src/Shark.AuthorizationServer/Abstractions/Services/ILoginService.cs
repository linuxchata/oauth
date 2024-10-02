namespace Shark.AuthorizationServer.Abstractions.Services;

public interface ILoginService
{
    Task SignIn(string userName, string[] selectedScopes);
}