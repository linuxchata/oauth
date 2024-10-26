namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IRedirectionService
{
    string? GetClientId(string returnUrl);

    string BuildAuthorizeUrl(string returnUrl, string[] scopes);

    string BuildClientCallbackUrl(string redirectUri, string code, string[] scopes, string? state);

    string BuildClientCallbackUrl(string redirectUri, string token, string tokenType);
}