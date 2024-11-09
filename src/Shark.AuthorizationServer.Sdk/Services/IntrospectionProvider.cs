using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Configurations;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

internal sealed class IntrospectionProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<BearerTokenAuthenticationOptions> options) : IIntrospectionProvider
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;
    private readonly BearerTokenAuthenticationOptions _configuration = options.Value;

    public async Task<bool> GetTokenStatus(string token)
    {
        var baseUri = new Uri(_configuration.AuthorizationServerUri);
        var introspectEndpoint = new Uri(baseUri, AuthorizationServerEndpoint.Introspect);

        var result = await Post(introspectEndpoint.ToString(), token);

        var introspectResponse =
            JsonSerializer.Deserialize<IntrospectResponse>(result) ??
            throw new ArgumentException($"Response from {AuthorizationServerEndpoint.Introspect} endpoint is empty");

        return introspectResponse.Active;
    }

    private async Task<string> Post(string endpoint, string token)
    {
        var formData = new List<KeyValuePair<string, string>>
        {
            new(QueryParam.Token, token),
        };

        var content = new FormUrlEncodedContent(formData);

        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = GetAuthorizationHeaderValue();
        var response = await httpClient.PostAsync(endpoint, content);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync();
    }

    private AuthenticationHeaderValue GetAuthorizationHeaderValue()
    {
        var credentials = Encoding.UTF8.GetBytes(
            _configuration.TokenIntrospection!.ClientId + ":" + _configuration.TokenIntrospection!.ClientSecret);
        var encodedCredentials = Convert.ToBase64String(credentials);
        return new AuthenticationHeaderValue("Basic", encodedCredentials);
    }
}