using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Client.Models;

namespace Shark.AuthorizationServer.Client.Services;

public interface IBearerTokenHandlingService
{
    string? GetAccessToken(IHeaderDictionary headers);

    bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity);
}