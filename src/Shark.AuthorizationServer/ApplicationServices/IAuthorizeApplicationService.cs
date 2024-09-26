using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IAuthorizeApplicationService
{
    void Execute(AuthorizeInternalRequest authorizeInternalRequest);
}
