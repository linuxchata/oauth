using Microsoft.Extensions.Logging;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Core.Abstractions.Validators;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Register;

namespace Shark.AuthorizationServer.Core.Validators;

public sealed class RegisterValidator(
    ILogger<RegisterValidator> logger) : BaseValidator<RegisterInternalBadRequestResponse>, IRegisterValidator
{
    private readonly ILogger<RegisterValidator> _logger = logger;

    public RegisterInternalBadRequestResponse? ValidatePostRequest(RegisterInternalRequest request)
    {
        return CheckAll(
            ValidateRedirectUris(request.RedirectUris),
            ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod),
            ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes),
            ValidateClientName(request.ClientName),
            ValidateClientUri(request.ClientUri),
            ValidateLogoUri(request.LogoUri),
            ValidateAudience(request.Audience));
    }

    public RegisterInternalBadRequestResponse? ValidatePutRequest(RegisterUpdateInternalRequest request)
    {
        return CheckAll(
            ValidateRedirectUris(request.RedirectUris),
            ValidateTokenEndpointAuthMethod(request.TokenEndpointAuthMethod),
            ValidateGrandTypesAndResponseTypes(request.GrantTypes, request.ResponseTypes),
            ValidateClientName(request.ClientName),
            ValidateClientUri(request.ClientUri),
            ValidateLogoUri(request.LogoUri),
            ValidateAudience(request.Audience));
    }

    public RegisterInternalBadRequestResponse? ValidateClientId(string clientId, string requestClientId)
    {
        if (!clientId.EqualsTo(requestClientId))
        {
            _logger.LogWarning("Invalid client identifier");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    public RegisterInternalBadRequestResponse? ValidateClientSecret(string clientSecret, string? requestClientSecret)
    {
        if (!string.IsNullOrWhiteSpace(requestClientSecret) &&
            !requestClientSecret.EqualsTo(clientSecret))
        {
            _logger.LogWarning("Invalid client secret");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateRedirectUris(string[] redirectUris)
    {
        if (redirectUris == null || redirectUris.Length == 0)
        {
            _logger.LogWarning("Invalid redirect URLs");
            return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
        }

        foreach (var redirectUri in redirectUris)
        {
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                _logger.LogWarning("Invalid redirect URL [{RedirectUri}]", redirectUri.Sanitize());
                return new RegisterInternalBadRequestResponse(Error.InvalidRedirectUri);
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateTokenEndpointAuthMethod(string? tokenEndpointAuthMethod)
    {
        if (!string.IsNullOrWhiteSpace(tokenEndpointAuthMethod) &&
            !tokenEndpointAuthMethod.EqualsTo(ClientAuthMethod.ClientSecretBasic))
        {
            _logger.LogWarning("Invalid token endpoint authentication method");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateGrandTypesAndResponseTypes(string grantTypes, string responseTypes)
    {
        if (string.IsNullOrWhiteSpace(grantTypes))
        {
            _logger.LogWarning("Invalid grant types");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        if (string.IsNullOrWhiteSpace(responseTypes))
        {
            _logger.LogWarning("Invalid response types");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        var grandTypesList = grantTypes.Split(' ').ToList();
        var responseTypesList = responseTypes.Split(' ').ToList();
        foreach (var grandType in grandTypesList)
        {
            if (!GrantType.Allowed.Contains(grandType))
            {
                _logger.LogWarning(
                    "Unsupported grant type [{GrantType}] by server",
                    grandType.Sanitize());
                return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
            }

            if (grandType.EqualsTo(GrantType.AuthorizationCode))
            {
                var codeResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Code));

                if (codeResponseType == null)
                {
                    _logger.LogWarning(
                        "Grant type [{GrantType}] must include response type [{ResponseType}]",
                        GrantType.AuthorizationCode,
                        ResponseType.Code);
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
            else if (grandType.EqualsTo(GrantType.Implicit))
            {
                var tokenResponseType = responseTypesList.Find(t => t.EqualsTo(ResponseType.Token));

                if (tokenResponseType == null)
                {
                    _logger.LogWarning(
                        "Grant type [{GrantType}] must include response type [{ResponseType}]",
                        GrantType.Implicit,
                        ResponseType.Token);
                    return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
                }
            }
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientName(string clientName)
    {
        if (string.IsNullOrWhiteSpace(clientName))
        {
            _logger.LogWarning("Invalid client name");
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateClientUri(string? clientUri)
    {
        if (!string.IsNullOrWhiteSpace(clientUri) &&
            !Uri.IsWellFormedUriString(clientUri, UriKind.Absolute))
        {
            _logger.LogWarning("Invalid client URL [{ClientUri}]", clientUri.Sanitize());
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateLogoUri(string? logoUri)
    {
        if (!string.IsNullOrWhiteSpace(logoUri) &&
            !Uri.IsWellFormedUriString(logoUri, UriKind.Absolute))
        {
            _logger.LogWarning("Invalid logo URL [{LogoUri}]", logoUri.Sanitize());
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }

    private RegisterInternalBadRequestResponse? ValidateAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience) ||
            !Uri.IsWellFormedUriString(audience, UriKind.Absolute))
        {
            _logger.LogWarning("Invalid audience [{Audience}]", audience.Sanitize());
            return new RegisterInternalBadRequestResponse(Error.InvalidClientMetadata);
        }

        return null;
    }
}