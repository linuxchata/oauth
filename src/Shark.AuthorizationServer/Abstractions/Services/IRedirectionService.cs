namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IRedirectionService
{
    string? GetClientId(string returnUrl);

    string BuildAuthorizeUrl(string authorizationServerUri, string returnUrl, string[] scopes);

    string BuildClientCallbackUrl(string redirectUri, string code, string[] scopes, string? state);

    string BuildClientCallbackUrl(string redirectUri, string token, string tokenType);
}