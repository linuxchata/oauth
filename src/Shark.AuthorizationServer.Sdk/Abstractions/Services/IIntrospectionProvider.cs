namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IIntrospectionProvider
{
    Task<bool> GetTokenStatus(string token);
}