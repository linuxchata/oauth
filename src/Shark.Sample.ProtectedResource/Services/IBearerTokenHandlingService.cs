using Shark.Sample.ProtectedResource.Models;

namespace Shark.Sample.ProtectedResource.Services;

public interface IBearerTokenHandlingService
{
    string? GetAccessToken(IHeaderDictionary headers);

    bool ParseAccessToken(string accessToken, out TokenIdentity tokenIdentity);
}