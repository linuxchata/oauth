using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface ITokenApplicationService
{
    TokenInternalBaseResponse Execute(TokenInternalRequest request);
}
