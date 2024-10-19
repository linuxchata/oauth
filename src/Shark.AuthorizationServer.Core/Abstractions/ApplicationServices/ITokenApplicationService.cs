using System.Security.Claims;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;

namespace Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

public interface ITokenApplicationService
{
    Task<TokenInternalBaseResponse> Execute(TokenInternalRequest request, ClaimsPrincipal claimsPrincipal);
}
