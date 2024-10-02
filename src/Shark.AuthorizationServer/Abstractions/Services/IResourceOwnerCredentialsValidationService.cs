namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IResourceOwnerCredentialsValidationService
{
    bool ValidateCredentials(string? username, string? password);
}
