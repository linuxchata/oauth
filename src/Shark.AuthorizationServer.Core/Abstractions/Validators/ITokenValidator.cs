using System.Security.Claims;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Validators;

public interface ITokenValidator
{
    TokenInternalBadRequestResponse? ValidateRequest(
        TokenInternalRequest request,
        Client? client,
        ClaimsPrincipal claimsPrincipal);
}