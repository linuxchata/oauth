namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IClientAccessTokenCachedService
{
    Task<string> Get(string grantType, string? scope = null, string? username = null, string? password = null);

    void Invalidate(string grantType);
}