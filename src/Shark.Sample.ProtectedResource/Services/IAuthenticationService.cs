namespace Shark.Sample.ProtectedResource.Services;

public interface IAuthenticationService
{
    bool IsAuthenticated(IHeaderDictionary headers);
}