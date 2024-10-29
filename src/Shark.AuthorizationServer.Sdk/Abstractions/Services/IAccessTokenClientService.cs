namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IAccessTokenClientService
{
    Task<string> Get(string grantType, string? scope = null, string? username = null, string? password = null);

    void Invalidate(string grantType);
}