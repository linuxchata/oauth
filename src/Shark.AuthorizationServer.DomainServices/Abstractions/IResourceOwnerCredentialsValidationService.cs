namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IResourceOwnerCredentialsValidationService
{
    bool ValidateCredentials(string? username, string? password);
}
