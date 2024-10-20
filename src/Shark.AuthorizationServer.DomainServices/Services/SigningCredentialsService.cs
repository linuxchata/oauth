﻿using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class SigningCredentialsService(
    [FromKeyedServices("private")] RsaSecurityKey rsaSecurityKey,
    IOptions<AuthorizationServerConfiguration> options) : ISigningCredentialsService
{
    private readonly RsaSecurityKey _rsaSecurityKey = rsaSecurityKey;
    private readonly AuthorizationServerConfiguration _configuration = options.Value;

    public SigningCredentials GetSigningCredentials()
    {
        if (_configuration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            return GetHs256SigningCredentials();
        }
        else if (_configuration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            return GetRsa256SigningCredentials();
        }

        throw new InvalidOperationException($"Unsupported signature algorithms {_configuration.SecurityAlgorithms}");
    }

    private SigningCredentials GetHs256SigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);
        var securityKey = new SymmetricSecurityKey(key);
        return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
    }

    private SigningCredentials GetRsa256SigningCredentials()
    {
        return new SigningCredentials(_rsaSecurityKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
        };
    }
}