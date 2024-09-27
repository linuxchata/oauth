namespace Shark.AuthorizationServer.Services;

public interface ILoginService
{
    Task SignIn(string userName, string[] selectedScopes);
}