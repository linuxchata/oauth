using Shark.AuthorizationServer.Domain;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IProfileService
{
    Task<ProfileInfo> Get(string userId);
}