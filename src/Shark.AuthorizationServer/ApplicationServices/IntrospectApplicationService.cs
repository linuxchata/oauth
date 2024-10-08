using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class IntrospectApplicationService : IIntrospectApplicationService
{
    public IntrospectInternalBaseResponse Execute(IntrospectInternalRequest introspectInternalRequest)
    {
        return new IntrospectInternalResponse
        {
            Active = true,
        };
    }
}