namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface ILoginService
{
    Task SignIn(string userName, string[] selectedScopes);
}