using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Abstractions.Stores;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public sealed class AuthorizationClientService(
    IProofKeyForCodeExchangeService proofKeyForCodeExchangeService,
    IStateStore stateStore,
    IHttpContextAccessor httpContextAccessor,
    IOptions<AuthorizationServerConfiguration> options) : IAuthorizationClientService
{
    private readonly IProofKeyForCodeExchangeService _proofKeyForCodeExchangeService = proofKeyForCodeExchangeService;
    private readonly IStateStore _stateStore = stateStore;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public void LoginAuthorizationCodeFlow()
    {
        var state = GetState();

        var redirectUrl = BuildLoginPageUrlInternal(ResponseType.Code, state);

        RedirectInternal(redirectUrl);
    }

    public void LoginAuthorizationCodeFlowWithPkce()
    {
        var state = GetState();

        var pkce = _proofKeyForCodeExchangeService.Generate(state);

        var redirectUrl = BuildLoginPageUrlInternal(ResponseType.Code, state, pkce);

        RedirectInternal(redirectUrl);
    }

    public void LoginImplicitFlow()
    {
        var redirectUrl = BuildLoginPageUrlInternal(ResponseType.Token, null);

        RedirectInternal(redirectUrl);
    }

    private string GetState()
    {
        var state = Guid.NewGuid().ToString("N").ToLower();
        _stateStore.Add(GrantType.AuthorizationCode, state);

        return state;
    }

    private string BuildLoginPageUrlInternal(string responseType, string? state, ProofKeyForCodeExchange? pkce = null)
    {
        // Create Return URL
        var returnUrlBuilder = new UriBuilder(null, AuthorizationServerEndpoint.Authorize);
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
            Path = AuthorizationServerEndpoint.LoginPagePath,
        };
        var query = HttpUtility.ParseQueryString(loginPageUriBuilder.Query);
        query[QueryParam.ReturnUrl] = returnUrl;
        loginPageUriBuilder.Query = query.ToString();
        return loginPageUriBuilder.ToString();
    }

    private void RedirectInternal(string redirectUrl)
    {
        _httpContextAccessor.HttpContext?.Response.Redirect(redirectUrl);
    }
}