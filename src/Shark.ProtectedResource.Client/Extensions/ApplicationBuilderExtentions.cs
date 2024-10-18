using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Authentication;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Client.Models;
using Shark.AuthorizationServer.Client.Services;

namespace Shark.AuthorizationServer.Client.Extensions;

public static class ApplicationBuilderExtentions
{
    public static IServiceCollection AddSharkAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<BearerTokenAuthenticationOptions>(
            configuration.GetSection(BearerTokenAuthenticationOptions.Name));

        var bearerTokenAuthenticationOptions = new BearerTokenAuthenticationOptions();
        configuration.GetSection(BearerTokenAuthenticationOptions.Name).Bind(bearerTokenAuthenticationOptions);

        var rsaSecurityKey = GetRsaSecurityKey(services).GetAwaiter().GetResult();
        services.AddSingleton(rsaSecurityKey);

        services.AddTransient<IBearerTokenHandlingService, BearerTokenHandlingService>();

        services
            .AddAuthentication(Scheme.Bearer)
            .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
                Scheme.Bearer,
                options => options = bearerTokenAuthenticationOptions);

        services
            .AddAuthorizationBuilder()
            .AddPolicy(Scope.Read, policy =>
            {
                policy.AddAuthenticationSchemes(Scheme.Bearer);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(ClaimType.Scope, Scope.Read);
            })
            .AddPolicy(Scope.Delete, policy =>
            {
                policy.AddAuthenticationSchemes(Scheme.Bearer);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(ClaimType.Scope, Scope.Delete);
            });

        return services;
    }

    private static async Task<RsaSecurityKey> GetRsaSecurityKey(IServiceCollection services)
    {
        services.AddHttpClient();
        services.AddTransient<IPublicKeyProvider, PublicKeyProvider>();

        var serviceProvider = services.BuildServiceProvider();
        var publicKeyProvider =
            serviceProvider.GetService(typeof(IPublicKeyProvider)) as IPublicKeyProvider ??
            throw new InvalidOperationException("Public Key provider cannot be resolved");

        var configurationJwksResponse =
            await publicKeyProvider.Get() ??
            throw new InvalidOperationException("JSON Web Key Set configuration is empty");

        return GetRsaSecurityKey(configurationJwksResponse);
    }

    private static RsaSecurityKey GetRsaSecurityKey(ConfigurationJwksResponse configurationJwksResponse)
    {
        if (!string.Equals(configurationJwksResponse.KeyType, "RSA", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Unssuported key type {configurationJwksResponse.KeyType}");
        }

        if (!string.Equals(configurationJwksResponse.Algorithm, SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"Unssuported algorithm {configurationJwksResponse.Algorithm}");
        }

        var rsa = RSA.Create();

        var rsaParams = new RSAParameters
        {
            Modulus = Convert.FromBase64String(configurationJwksResponse.Modulus),
            Exponent = Convert.FromBase64String(configurationJwksResponse.Exponent),
        };

        rsa.ImportParameters(rsaParams);

        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = configurationJwksResponse.KeyId
        };

        return securityKey;
    }
}