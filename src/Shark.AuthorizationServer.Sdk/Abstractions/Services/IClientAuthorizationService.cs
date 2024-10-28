namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IClientAuthorizationService
{
    void LoginAuthorizationCodeFlow();

    void LoginAuthorizationCodeFlowWithPkce();

    void LoginImplicitFlow();
}