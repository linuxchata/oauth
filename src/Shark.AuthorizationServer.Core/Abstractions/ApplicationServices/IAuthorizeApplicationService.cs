using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IAuthorizeApplicationService
{
    Task<IAuthorizeInternalResponse> Execute(AuthorizeInternalRequest request);
}
