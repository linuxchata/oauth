using Microsoft.IdentityModel.Tokens;

namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface ISigningCredentialsService
{
    SigningCredentials GetSigningCredentials();
}
