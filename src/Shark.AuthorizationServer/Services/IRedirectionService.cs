namespace Shark.AuthorizationServer.Services;

public interface IRedirectionService
{
    string? GetClientId(string returnUrl);

    string BuildAuthorizeUrl(string authorizationServerUri, string returnUrl, string[] scopes);

    string BuildClientCallbackUrl(string redirectUrl, string code, string[] scopes, string state);
}