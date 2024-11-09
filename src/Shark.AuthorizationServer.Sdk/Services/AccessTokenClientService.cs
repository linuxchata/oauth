using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Abstractions.Stores;

namespace Shark.AuthorizationServer.Sdk.Services;

public sealed class AccessTokenClientService(
    ISecureTokenStore secureTokenStore,
    IAccessTokenClientInternalService clientAccessTokenService) : IAccessTokenClientService
{
    private const string MissingAccessTokenErrorMessage = "Missing access token";
    private const string MissingAccessTokenAndRefreshTokenErrorMessage = "Missing access token and refresh token";

    private readonly ISecureTokenStore _secureTokenStore = secureTokenStore;
    private readonly IAccessTokenClientInternalService _clientAccessTokenService = clientAccessTokenService;

    public async Task<string> Get(
        string grantType,
        string? scope = null,
        string? username = null,
        string? password = null)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(grantType, nameof(grantType));

        if (grantType.EqualsTo(GrantType.AuthorizationCode))
        {
            return await GetForAuthorizationCodeFlow();
        }
        else if (grantType.EqualsTo(GrantType.Implicit))
        {
            return GetForImplicitFlow();
        }
        else if (grantType.EqualsTo(GrantType.ClientCredentials))
        {
            return await GetForForClientCredentialsFlow(scope);
        }
        else if (grantType.EqualsTo(GrantType.ResourceOwnerCredentials))
        {
            ArgumentNullException.ThrowIfNullOrWhiteSpace(username, nameof(username));
            ArgumentNullException.ThrowIfNullOrWhiteSpace(password, nameof(password));

            return await GetForForPasswordFlow(username, password, scope);
        }

        throw new ArgumentException("Unsupported grant type");
    }

    public void Invalidate(string grantType)
    {
        _secureTokenStore.RemoveAccessToken(grantType);
    }

    private async Task<string> GetForAuthorizationCodeFlow()
    {
        var accessToken = _secureTokenStore.GetAccessToken(GrantType.AuthorizationCode);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var refreshToken = _secureTokenStore.GetRefreshToken(GrantType.AuthorizationCode);
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new ArgumentException(MissingAccessTokenAndRefreshTokenErrorMessage);
        }

        var secureToken = await _clientAccessTokenService.RequestForRefreshTokenFlow(refreshToken, null!);
        _secureTokenStore.Add(GrantType.AuthorizationCode, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private string GetForImplicitFlow()
    {
        var accessToken = _secureTokenStore.GetAccessToken(GrantType.Implicit);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private async Task<string> GetForForClientCredentialsFlow(string? scope)
    {
        var accessToken = _secureTokenStore.GetAccessToken(GrantType.ClientCredentials);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var secureToken = await _clientAccessTokenService.RequestForClientCredentialsFlow(scope);
        _secureTokenStore.Add(GrantType.ClientCredentials, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }

    private async Task<string> GetForForPasswordFlow(string username, string password, string? scope)
    {
        var accessToken = _secureTokenStore.GetAccessToken(GrantType.ResourceOwnerCredentials);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var secureToken = await _clientAccessTokenService.RequestForPasswordFlow(username, password, scope);
        _secureTokenStore.Add(GrantType.ResourceOwnerCredentials, secureToken);
        return secureToken.AccessToken ?? throw new ArgumentException(MissingAccessTokenErrorMessage);
    }
}