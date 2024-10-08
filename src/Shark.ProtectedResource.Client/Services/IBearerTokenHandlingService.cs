using Microsoft.AspNetCore.Http;
using Shark.ProtectedResource.Client.Models;

namespace Shark.ProtectedResource.Client.Services
{
    public interface IBearerTokenHandlingService
    {
        string? GetAccessToken(IHeaderDictionary headers);

        bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity);
    }
}