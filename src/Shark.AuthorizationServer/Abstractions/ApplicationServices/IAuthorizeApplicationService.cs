using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Abstractions.ApplicationServices;

public interface IAuthorizeApplicationService
{
    AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest authorizeInternalRequest);
}
