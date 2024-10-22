﻿using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Responses.Configuration;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class ConfigurationApplicationService(
    IOptions<AuthorizationServerConfiguration> options,
    IOptions<AuthorizationServerSecurityConfiguration> securityOptions,
    [FromKeyedServices("public")] RsaSecurityKey? rsaSecurityKey = null,
    [FromKeyedServices("public")] X509SecurityKey? x509SecurityKey = null,
    SigningCertificate? signingCertificate = null) : IConfigurationApplicationService
{
    private const string SigPublicKeyUse = "sig";
    private const string Hs256KeyType = "HS256";
    private const string RsaKeyType = "RSA";

    private readonly RsaSecurityKey? _rsaSecurityKey = rsaSecurityKey;
    private readonly X509SecurityKey? _x509SecurityKey = x509SecurityKey;
    private readonly SigningCertificate? _signingCertificate = signingCertificate;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;
    private readonly AuthorizationServerSecurityConfiguration _securityConfiguration = securityOptions.Value;

    public Task<ConfigurationResponse> Get()
    {
        var baseUrl = new Uri(_configuration.AuthorizationServerUri);
        var authorizeEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Authorize);
        var tokenEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Token);
        var introspectEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Introspect);
        var revokeEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Revoke);
        var registerEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Register);
        var userInfoEndpoint = new Uri(baseUrl, AuthorizationServerEndpoint.UserInfo);
        var deviceAuthorizationEndpoint = new Uri(baseUrl, AuthorizationServerEndpoint.DeviceAuthorization);
        var jsonWebKeySetEndpoint = new Uri(baseUrl, AuthorizationServerEndpoint.ConfigurationJwks);

        var response = new ConfigurationResponse
        {
            AuthorizeEndpoint = authorizeEndpointUri.ToString(),
            TokenEndpoint = tokenEndpointUri.ToString(),
            IntrospectEndpoint = introspectEndpointUri.ToString(),
            RevokeEndpoint = revokeEndpointUri.ToString(),
            RegisterEndpoint = registerEndpointUri.ToString(),
            UserInfoEndpoint = userInfoEndpoint.ToString(),
            DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint.ToString(),
            JsonWebKeySetEndpoint = jsonWebKeySetEndpoint.ToString(),
            Issuer = _configuration.Issuer,
            CodeChallengeMethodsSupported = [CodeChallengeMethod.Plain, CodeChallengeMethod.Sha256],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken, GrantType.Implicit, GrantType.ClientCredentials, GrantType.ResourceOwnerCredentials, GrantType.DeviceCode],
            SecurityAlgorithms = [_configuration.SecurityAlgorithms],
        };

        return Task.FromResult(response);
    }

    public Task<ConfigurationJwksResponse> GetJsonWebKeySet()
    {
        if (_securityConfiguration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return GetRs256Response();
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GetHs256Response();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_securityConfiguration.SecurityAlgorithms}");
    }

    private Task<ConfigurationJwksResponse> GetRs256Response()
    {
        RSA? rsa;
        if (_securityConfiguration.UseRsaCertificate)
        {
            var securityKey = _x509SecurityKey ??
                throw new InvalidOperationException("X509 security key is not registered");

            rsa = securityKey.PublicKey as RSA;
        }
        else
        {
            var securityKey = _rsaSecurityKey ??
                throw new InvalidOperationException("RSA security key is not registered");

            rsa = securityKey.Rsa;
        }

        string? exponent = null;
        string? modulus = null;
        if (rsa is not null)
        {
            var parameters = rsa.ExportParameters(false);
            exponent = Convert.ToBase64String(parameters.Exponent ?? []);
            modulus = Convert.ToBase64String(parameters.Modulus ?? []);
        }

        var response = new ConfigurationJwksResponse
        {
            Exponent = exponent,
            PublicKeyUse = SigPublicKeyUse,
            Algorithm = _securityConfiguration.SecurityAlgorithms,
            KeyType = RsaKeyType,
            KeyId = _securityConfiguration.KeyId,
            Modulus = modulus,
            SymmetricKey = null,
            X509CertificateChain = _signingCertificate?.X509CertificateChain,
        };

        return Task.FromResult(response);
    }

    private Task<ConfigurationJwksResponse> GetHs256Response()
    {
        var response = new ConfigurationJwksResponse
        {
            Exponent = null,
            PublicKeyUse = SigPublicKeyUse,
            Algorithm = _securityConfiguration.SecurityAlgorithms,
            KeyType = Hs256KeyType,
            KeyId = _configuration.KeyId,
            Modulus = null,
            SymmetricKey = _securityConfiguration.SymmetricSecurityKey,
            X509CertificateChain = null,
        };

        return Task.FromResult(response);
    }
}