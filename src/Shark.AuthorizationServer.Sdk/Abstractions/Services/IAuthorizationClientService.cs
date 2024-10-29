namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IAuthorizationClientService
{
    void LoginAuthorizationCodeFlow();

    void LoginAuthorizationCodeFlowWithPkce();

    void LoginImplicitFlow();
}