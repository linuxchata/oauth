namespace Shark.AuthorizationServer.Services;

public interface IRedirectionService
{
    string BuildRedirectUrl(string redirectUrl, string code, string[] scopes, string state);
}