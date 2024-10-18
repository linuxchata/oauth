using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IAuthorizeApplicationService
{
    AuthorizeInternalBaseResponse Execute(AuthorizeInternalRequest authorizeInternalRequest);
}
