using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

public sealed class PublicKeyProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<BearerTokenAuthenticationOptions> options) : IPublicKeyProvider
{
    private const string WellKnownConfigurationPath = ".well-known/openid-configuration";

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
        var wellKnownConfigurationEndpoint = new Uri(baseUri, WellKnownConfigurationPath);

        using var httpClient = _httpClientFactory.CreateClient();
        var response = await httpClient.GetAsync(wellKnownConfigurationEndpoint);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadAsStringAsync();

        var configurationResponse =
            JsonSerializer.Deserialize<ConfigurationResponse>(result) ??
            throw new ArgumentException("Response from .well-known/openid-configuration endpoint is empty");

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