using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface ITokenApplicationService
{
    TokenInternalBaseResponse Execute(TokenInternalRequest request);
}
