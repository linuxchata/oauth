using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class ConfigurationJwksProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<BearerTokenAuthenticationOptions> options) : IConfigurationJwksProvider
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;

    public async Task<ConfigurationJwksResponse> Get()
    {
        var jsonWebKeySetEndpoint = await GetJsonWebKeySetEndpoint();

        return await GetConfigurationJwks(jsonWebKeySetEndpoint);
    }

    private async Task<string> GetJsonWebKeySetEndpoint()
    {
        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var wellKnownConfigurationEndpoint = new Uri(baseUri, AuthorizationServerEndpoint.WellKnownConfigurationPath);

        using var httpClient = _httpClientFactory.CreateClient();
        var response = await httpClient.GetAsync(wellKnownConfigurationEndpoint);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadAsStringAsync();

        var configurationResponse =
            JsonSerializer.Deserialize<ConfigurationResponse>(result) ??
            throw new ArgumentException($"Response from {AuthorizationServerEndpoint.WellKnownConfigurationPath} endpoint is empty");

        return configurationResponse.JsonWebKeySetEndpoint!;
    }

    private async Task<ConfigurationJwksResponse> GetConfigurationJwks(string jsonWebKeySetEndpoint)
    {
        using var httpClient = _httpClientFactory.CreateClient();
        var response = await httpClient.GetAsync(jsonWebKeySetEndpoint);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadAsStringAsync();

        var configurationJwksResponse =
            JsonSerializer.Deserialize<ConfigurationJwksResponse>(result) ??
            throw new ArgumentException("Response from JSON Web Key Set endpoint is empty");

        return configurationJwksResponse!;
    }
}