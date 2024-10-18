using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Constants;
using Shark.AuthorizationServer.Core.Responses;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.Core.ApplicationServices;

public sealed class ConfigurationApplicationService(
    RsaSecurityKey rsaSecurityKey,
    IOptions<AuthorizationServerConfiguration> options) : IConfigurationApplicationService
{
    private const string SigPublicKeyUse = "sig";
    private const string RsaKeyType = "RSA";

    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public ConfigurationResponse Get()
    {
        var baseUrl = new Uri(_configuration.AuthorizationServerUri);
        var authorizeEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Authorize);
        var tokenEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Token);
        var introspectEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Introspect);
        var revokeEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Revoke);
        var registerEndpointUri = new Uri(baseUrl, AuthorizationServerEndpoint.Register);
        var jsonWebKeySetEndpoint = new Uri(baseUrl, AuthorizationServerEndpoint.ConfigurationJwks);

        return new ConfigurationResponse
        {
            AuthorizeEndpoint = authorizeEndpointUri.ToString(),
            TokenEndpoint = tokenEndpointUri.ToString(),
            IntrospectEndpoint = introspectEndpointUri.ToString(),
            RevokeEndpoint = revokeEndpointUri.ToString(),
            RegisterEndpoint = registerEndpointUri.ToString(),
            JsonWebKeySetEndpoint = jsonWebKeySetEndpoint.ToString(),
            Issuer = _configuration.Issuer,
            CodeChallengeMethodsSupported = [CodeChallengeMethod.Plain, CodeChallengeMethod.Sha256],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken, GrantType.Implicit, GrantType.ResourceOwnerCredentials, GrantType.ClientCredentials],
            SecurityAlgorithms = [_configuration.SecurityAlgorithms],
        };
    }

    public ConfigurationJwksResponse GetJsonWebKeySet()
    {
        // Danger zone - do not expose private key
        var parameters = _rsaSecurityKey.Rsa.ExportParameters(false);
        var exponent = parameters.Exponent ?? [];
        var modulus = parameters.Modulus ?? [];

        return new ConfigurationJwksResponse
        {
            Exponent = Convert.ToBase64String(exponent),
            PublicKeyUse = SigPublicKeyUse,
            Algorithm = SecurityAlgorithms.RsaSha256,
            KeyType = RsaKeyType,
            KeyId = _configuration.KeyId,
            Modulus = Convert.ToBase64String(modulus),
        };
    }
}