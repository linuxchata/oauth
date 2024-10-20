using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class SigningCredentialsService(
    IOptions<AuthorizationServerConfiguration> options,
    [FromKeyedServices("private")] RsaSecurityKey? rsaSecurityKey = null,
    SymmetricSecurityKey? symmetricSecurityKey = null) : ISigningCredentialsService
{
    private readonly RsaSecurityKey? _rsaSecurityKey = rsaSecurityKey;
    private readonly SymmetricSecurityKey? _symmetricSecurityKey = symmetricSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public SigningCredentials GetSigningCredentials()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return new SigningCredentials(_symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
            };
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }
}