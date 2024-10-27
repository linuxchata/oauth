using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Abstractions.Validators;

public interface IRegisterValidator
{
    RegisterInternalBadRequestResponse? ValidatePostRequest(RegisterInternalRequest request);

    RegisterInternalBadRequestResponse? ValidatePutRequest(RegisterUpdateInternalRequest request);

    RegisterInternalBadRequestResponse? ValidateClientId(string clientId, string requestClientId);

    RegisterInternalBadRequestResponse? ValidateClientSecret(string clientSecret, string? requestClientSecret);
}