using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IBearerTokenHandler
{
    string? GetAccessToken(IHeaderDictionary headers);

    Task<TokenIdentity?> ParseAccessToken(string accessToken);
}