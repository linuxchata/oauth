using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IIntrospectApplicationService
{
    IntrospectInternalBaseResponse Execute(IntrospectInternalRequest request);
}