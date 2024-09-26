namespace Shark.AuthorizationServer.Services;

public interface ILoginService
{
    void PostLogin(string redirectBaseUrl, string code, string[] selectedScopes, string state);
}