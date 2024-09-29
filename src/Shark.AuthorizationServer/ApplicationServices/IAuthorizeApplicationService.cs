using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IAuthorizeApplicationService
{
    AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest authorizeInternalRequest);
}
