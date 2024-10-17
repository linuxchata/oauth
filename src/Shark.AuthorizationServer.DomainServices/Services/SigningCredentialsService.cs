using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class SigningCredentialsService(
    RsaSecurityKey rsaSecurityKey,
    IOptions<AuthorizationServerConfiguration> options) : ISigningCredentialsService
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public SigningCredentials GenerateSigningCredentials()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GenerateSigningCredentialsHs256();
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return GenerateSigningCredentialsRsa256();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }

    private SigningCredentials GenerateSigningCredentialsHs256()
    {
        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    }

    private SigningCredentials GenerateSigningCredentialsRsa256()
    {
        return new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
        };
    }
}