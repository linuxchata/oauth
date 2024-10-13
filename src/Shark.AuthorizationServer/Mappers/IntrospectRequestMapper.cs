using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class IntrospectRequestMapper
{
    public static IntrospectInternalRequest ToInternalRequest(this IntrospectRequest request)
    {
        return new IntrospectInternalRequest
        {
            Token = request.token,
        };
    }
}