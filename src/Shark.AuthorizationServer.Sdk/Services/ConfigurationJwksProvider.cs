using System.Text.Json;
using Microsoft.Extensions.Options;
using Polly.Registry;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Configurations;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class ConfigurationJwksProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<BearerTokenAuthenticationOptions> options,
    ResiliencePipelineProvider<string>? resiliencePipelineProvider = null) : IConfigurationJwksProvider
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;
    private readonly ResiliencePipelineProvider<string>? _resiliencePipelineProvider = resiliencePipelineProvider;

    public async Task<ConfigurationJwksResponse> Get()
    {
        var jsonWebKeySetEndpoint = await GetJsonWebKeySetEndpoint();

        return await GetConfigurationJwks(jsonWebKeySetEndpoint);
    }

    private async Task<string> GetJsonWebKeySetEndpoint()
    {
        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var wellKnownConfigurationEndpoint = new Uri(baseUri, AuthorizationServerEndpoint.WellKnownConfigurationPath);

        var result = await Get(wellKnownConfigurationEndpoint.ToString());

        var configurationResponse =
            JsonSerializer.Deserialize<ConfigurationResponse>(result) ??
            throw new ArgumentException($"Response from {AuthorizationServerEndpoint.WellKnownConfigurationPath} endpoint is empty");

        return configurationResponse.JsonWebKeySetEndpoint!;
    }

    private async Task<ConfigurationJwksResponse> GetConfigurationJwks(string jsonWebKeySetEndpoint)
    {
        var result = await Get(jsonWebKeySetEndpoint);

        var configurationJwksResponse =
            JsonSerializer.Deserialize<ConfigurationJwksResponse>(result) ??
            throw new ArgumentException("Response from JSON Web Key Set endpoint is empty");

        return configurationJwksResponse!;
    }

    private async Task<string> Get(string endpoint)
    {
        if (_configuration.RetryConfiguration?.Enabled ?? false)
        {
            return await GetWithRetry(endpoint);
        }
        else
        {
            return await GetInternal(endpoint, CancellationToken.None);
        }
    }

    private async Task<string> GetWithRetry(string endpoint)
    {
        if (_resiliencePipelineProvider == null)
        {
            throw new InvalidOperationException("Retry logic is not properly configured");
        }

        string? result = null;

        var pipeline = _resiliencePipelineProvider.GetPipeline("configuration");
        await pipeline.ExecuteAsync(async cancellationToken =>
        {
            result = await GetInternal(endpoint, cancellationToken);
        });

        return result ?? throw new InvalidOperationException("Failed to get authorization server configuration");
    }

    private async Task<string> GetInternal(string endpoint, CancellationToken cancellationToken)
    {
        using var httpClient = _httpClientFactory.CreateClient();
        var response = await httpClient.GetAsync(endpoint, cancellationToken: cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken);
    }
}