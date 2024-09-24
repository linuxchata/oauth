using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IAuthorizeApplicationService
{
    AuthorizeInternalBaseResponse Execute(string clientId, string redirect_url);
}
