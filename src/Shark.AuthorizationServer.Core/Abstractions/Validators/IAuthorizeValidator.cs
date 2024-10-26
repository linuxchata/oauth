using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;
using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.Core.Abstractions.Validators;

public interface IAuthorizeValidator
{
    AuthorizeInternalBadRequestResponse? ValidateRequest(AuthorizeInternalRequest request, Client? client);
}