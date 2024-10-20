using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

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

        return services;
    }

    private static async Task<RsaSecurityKey> GetRsaSecurityKey(IServiceCollection services)
    {
        services.AddHttpClient();
        services.TryAddTransient<IPublicKeyProvider, PublicKeyProvider>();
        services.TryAddTransient<IRsaSecurityKeyProvider, RsaSecurityKeyNetworkProvider>();

        var serviceProvider = services.BuildServiceProvider();
        var rsaSecurityKeyProvider =
            serviceProvider.GetService(typeof(IRsaSecurityKeyProvider)) as IRsaSecurityKeyProvider ??
            throw new InvalidOperationException("RSA Security Key provider cannot be resolved");

        return await rsaSecurityKeyProvider.GetRsaSecurityKey();
    }
}