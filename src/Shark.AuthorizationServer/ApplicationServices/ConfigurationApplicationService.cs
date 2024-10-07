using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.ApplicationServices;

public sealed class ConfigurationApplicationService(
    IOptions<AuthorizationServerConfiguration> options) : IConfigurationApplicationService
{
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public ConfigurationResponse Get(string scheme, string host, int port)
    {
        var baseUrl = new UriBuilder(scheme, host, port);
        var authorizeEndpointUri = new Uri(baseUrl.Uri, "authorize");
        var tokenEndpointUri = new Uri(baseUrl.Uri, "token");

        return new ConfigurationResponse
        {
            AuthorizeEndpoint = authorizeEndpointUri.ToString(),
            TokenEndpoint = tokenEndpointUri.ToString(),
            Issuer = _configuration.Issuer,
            CodeChallengeMethodsSupported = [CodeChallengeMethod.Plain, CodeChallengeMethod.Sha256],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken, GrantType.Implicit, GrantType.ResourceOwnerCredentials, GrantType.ClientCredentials],
            SecurityAlgorithms = [_configuration.SecurityAlgorithms]
        };
    }
}