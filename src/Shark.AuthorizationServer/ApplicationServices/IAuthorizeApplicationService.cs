using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IAuthorizeApplicationService
{
    AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest authorizeInternalRequest);
}
