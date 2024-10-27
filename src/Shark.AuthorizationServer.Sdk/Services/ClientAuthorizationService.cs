using System.Web;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public sealed class ClientAuthorizationService(
    IOptions<AuthorizationServerConfiguration> options) : IClientAuthorizationService
{
    private const string LoginPagePath = "login";
    private const string AuthorizeEndpointPath = "authorize";

    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public string BuildLoginPageUrl(string responseType, string? state, ProofKeyForCodeExchange? pkce = null)
    {
        // Create Return URL
        var returnUrlBuilder = new UriBuilder(null, AuthorizeEndpointPath);
        var returnUrlBuilderQuery = HttpUtility.ParseQueryString(returnUrlBuilder.Query);
        returnUrlBuilderQuery[QueryParam.ResponseType] = responseType;
        returnUrlBuilderQuery[QueryParam.ClientId] = _configuration.ClientId;
        returnUrlBuilderQuery[QueryParam.RedirectUri] = _configuration.ClientCallbackEndpoint;
        returnUrlBuilderQuery[QueryParam.State] = state;

        if (pkce != null)
        {
            returnUrlBuilderQuery[QueryParam.CodeChallenge] = pkce.CodeChallenge;
            returnUrlBuilderQuery[QueryParam.CodeChallengeMethod] = pkce.CodeChallengeMethod;
        }

        returnUrlBuilder.Query = returnUrlBuilderQuery.ToString();
        var returnUrl = returnUrlBuilder.ToString();

        // Create authorization server login page URL
        var loginPageUriBuilder = new UriBuilder(_configuration.Address)
        {
            Path = LoginPagePath,
        };
        var query = HttpUtility.ParseQueryString(loginPageUriBuilder.Query);
        query[QueryParam.ReturnUrl] = returnUrl;
        loginPageUriBuilder.Query = query.ToString();
        return loginPageUriBuilder.ToString();
    }
}