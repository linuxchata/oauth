using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class RegisterValidator : IRegisterValidator
{
    public RegisterInternalBadRequestResponse? ValidatePostRequest(RegisterInternalRequest request)
    {
        var response = ValidateRedirectUris(request.RedirectUris);
        if (response != null)
        {
            return response;
        }

        response = ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod);
        if (response != null)
        {
            return response;
        }

        response = ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes);
        if (response != null)
        {
            return response;
        }

        response = ValidateClientName(request.ClientName);
        if (response != null)
        {
            return response;
        }

        response = ValidateClientUri(request.ClientUri);
        if (response != null)
        {
            return response;
        }

        response = ValidateLogoUri(request.LogoUri);
        if (response != null)
        {
            return response;
        }

        response = ValidateAudience(request.Audience);
        if (response != null)
        {
            return response;
        }

        return null;
    }

    public RegisterInternalBadRequestResponse? ValidatePutRequest(RegisterUpdateInternalRequest request)
    {
        var response = ValidateRedirectUris(request.RedirectUris);
        if (response != null)
        {
            return response;
        }

        response = ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod);
        if (response != null)
        {
            return response;
        }

        response = ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes);
        if (response != null)
        {
            return response;
        }

        response = ValidateClientName(request.ClientName);
        if (response != null)
        {
            return response;
        }

        response = ValidateClientUri(request.ClientUri);
        if (response != null)
        {
            return response;
        }

        response = ValidateLogoUri(request.LogoUri);
        if (response != null)
        {
            return response;
        }

        response = ValidateAudience(request.Audience);
        if (response != null)
        {
            return response;
        }

        return null;
    }

    public RegisterInternalBadRequestResponse? ValidateClientId(string clientId, string requestClientId)
    {
        if (!clientId.EqualsTo(requestClientId))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    public RegisterInternalBadRequestResponse? ValidateClientSecret(string clientSecret, string? requestClientSecret)
    {
        if (!string.IsNullOrWhiteSpace(requestClientSecret) &&
            !requestClientSecret.EqualsTo(clientSecret))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateRedirectUris(string[] redirectUris)
    {
        if (redirectUris == null || redirectUris.Length == 0)
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
        }

        foreach (var redirectUri in redirectUris)
        {
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
            }
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
    {
        if (!string.IsNullOrWhiteSpace(tokenEndpointAuthMethod) &&
            !tokenEndpointAuthMethod.EqualsTo(ClientAuthMethod.ClientSecretBasic))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateGrandTypesAndResponseTypes(string grantTypes, string responseTypes)
    {
        if (string.IsNullOrWhiteSpace(grantTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        if (string.IsNullOrWhiteSpace(responseTypes))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        var grandTypesList = grantTypes.Split(' ').ToList();
        var responseTypesList = responseTypes.Split(' ').ToList();
        foreach (var grandType in grandTypesList)
        {
            if (!GrantType.Allowed.Contains(grandType))
            {
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }

            if (grandType.EqualsTo(GrantType.AuthorizationCode))
            {
                var codeResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Code));

                if (codeResponseType == null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
            else if (grandType.EqualsTo(GrantType.Implicit))
            {
                var tokenResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Token));

                if (tokenResponseType == null)
                {
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateClientUri(string? clientUri)
    {
        if (!string.IsNullOrWhiteSpace(clientUri) &&
            !Uri.IsWellFormedUriString(clientUri, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateLogoUri(string? logoUri)
    {
        if (!string.IsNullOrWhiteSpace(logoUri) &&
            !Uri.IsWellFormedUriString(logoUri, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private static RegisterInternalBadRequestResponse? ValidateAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience) ||
            !Uri.IsWellFormedUriString(audience, UriKind.Absolute))
        {
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }
}