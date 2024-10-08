using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public interface IIntrospectApplicationService
{
    IntrospectInternalBaseResponse Execute(IntrospectInternalRequest introspectInternalRequest);
}