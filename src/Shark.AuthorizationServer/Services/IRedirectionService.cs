namespace Shark.AuthorizationServer.Services;

public interface IRedirectionService
{
    string BuildRedirectUrl(string redirectUrl, string code, string scope, string state);
}