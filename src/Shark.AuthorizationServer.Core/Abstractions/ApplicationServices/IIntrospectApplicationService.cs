using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Introspect;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface IIntrospectApplicationService
{
    Task<IIntrospectInternalResponse> Execute(IntrospectInternalRequest request);
}