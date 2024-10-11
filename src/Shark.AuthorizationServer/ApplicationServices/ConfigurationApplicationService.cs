using Microsoft.Extensions.Options;
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

    public ConfigurationResponse Get(string scheme, string host, int port)
    {
        var baseUrl = new UriBuilder(scheme, host, port);
        var authorizeEndpointUri = new Uri(baseUrl.Uri, "authorize");
        var tokenEndpointUri = new Uri(baseUrl.Uri, "token");
        var introspectEndpointUri = new Uri(baseUrl.Uri, "introspect");
        var jsonWebKeySetEndpoint = new Uri(baseUrl.Uri, ".well-known/openid-configuration/jwks");

        return new ConfigurationResponse
        {
            AuthorizeEndpoint = authorizeEndpointUri.ToString(),
            TokenEndpoint = tokenEndpointUri.ToString(),
            IntrospectEndpoint = introspectEndpointUri.ToString(),
            JsonWebKeySetEndpoint = jsonWebKeySetEndpoint.ToString(),
            Issuer = _configuration.Issuer,
            CodeChallengeMethodsSupported = [CodeChallengeMethod.Plain, CodeChallengeMethod.Sha256],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken, GrantType.Implicit, GrantType.ResourceOwnerCredentials, GrantType.ClientCredentials],
            SecurityAlgorithms = [_configuration.SecurityAlgorithms]
        };
    }

    public ConfigurationJwksResponse GetJsonWebKeySet()
    {
        // Danger zone - do not expose private key
        var exponent = _rsaSecurityKey.Rsa.ExportParameters(false).Exponent;
        var modulus = _rsaSecurityKey.Rsa.ExportSubjectPublicKeyInfo();

        return new ConfigurationJwksResponse
        {
            Exponent = Convert.ToBase64String(exponent!),
            PublicKeyUse = "sig",
            Algorithm = SecurityAlgorithms.RsaSha256,
            KeyType = "RSA",
            KeyId = _configuration.KeyId,
            Modulus = Convert.ToBase64String(modulus),
        };
    }
}