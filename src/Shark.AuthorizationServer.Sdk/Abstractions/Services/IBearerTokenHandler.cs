using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IBearerTokenHandler
{
    string? GetAccessToken(IHeaderDictionary headers);

    bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity);
}