using System.Security.Claims;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface ITokenApplicationService
{
    Task<ITokenInternalResponse> Execute(TokenInternalRequest request, ClaimsPrincipal clientIdentity);
}
