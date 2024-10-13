﻿using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class ConfigurationApplicationService(
    RsaSecurityKey rsaSecurityKey,
    IOptions<AuthorizationServerConfiguration> options) : IConfigurationApplicationService
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public ConfigurationResponse Get()
    {
        var baseUrl = new Uri(_configuration.AuthorizationServerUri);
        var authorizeEndpointUri = new Uri(baseUrl, "authorize");
        var tokenEndpointUri = new Uri(baseUrl, "token");
        var introspectEndpointUri = new Uri(baseUrl, "introspect");
        var revokeEndpointUri = new Uri(baseUrl, "revoke");
        var registerEndpointUri = new Uri(baseUrl, "register");
        var jsonWebKeySetEndpoint = new Uri(baseUrl, ".well-known/openid-configuration/jwks");

        return new ConfigurationResponse
        {
            AuthorizeEndpoint = authorizeEndpointUri.ToString(),
            TokenEndpoint = tokenEndpointUri.ToString(),
            IntrospectEndpoint = introspectEndpointUri.ToString(),
            RevokeEndpoint = revokeEndpointUri.ToString(),
            RegisterEndpoint = registerEndpointUri.ToString(),
            JsonWebKeySetEndpoint = jsonWebKeySetEndpoint.ToString(),
            Issuer = _configuration.IssuerUri,
            CodeChallengeMethodsSupported = [CodeChallengeMethod.Plain, CodeChallengeMethod.Sha256],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken, GrantType.Implicit, GrantType.ResourceOwnerCredentials, GrantType.ClientCredentials],
            SecurityAlgorithms = [_configuration.SecurityAlgorithms],
        };
    }

    public ConfigurationJwksResponse GetJsonWebKeySet()
    {
        // Danger zone - do not expose private key
        var exponent = _rsaSecurityKey.Rsa.ExportParameters(false).Exponent;
        //// var modulus = _rsaSecurityKey.Rsa.ExportSubjectPublicKeyInfo();
        var modulus = _rsaSecurityKey.Rsa.ExportParameters(false).Modulus;

        return new ConfigurationJwksResponse
        {
            Exponent = Convert.ToBase64String(exponent!),
            PublicKeyUse = "sig",
            Algorithm = SecurityAlgorithms.RsaSha256,
            KeyType = "RSA",
            KeyId = _configuration.KeyId,
            Modulus = Convert.ToBase64String(modulus!),
        };
    }
}