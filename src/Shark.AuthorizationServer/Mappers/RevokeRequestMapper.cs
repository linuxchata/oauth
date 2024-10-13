using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Mappers;

public static class RevokeRequestMapper
{
    public static RevokeInternalRequest ToInternalRequest(this RevokeRequest request)
    {
        return new RevokeInternalRequest
        {
            Token = request.token,
            TokenHint = request.token_hint,
        };
    }
}