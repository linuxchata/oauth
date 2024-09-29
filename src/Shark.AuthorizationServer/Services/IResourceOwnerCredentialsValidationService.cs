namespace Shark.AuthorizationServer.Services;

public interface IResourceOwnerCredentialsValidationService
{
    bool ValidateCredentials(string? username, string? password);
}
