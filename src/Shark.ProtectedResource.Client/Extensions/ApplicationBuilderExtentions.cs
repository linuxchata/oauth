using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Client.Authentication;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Client.Models;
using Shark.AuthorizationServer.Client.Services;
using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.Common.Abstractions;

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

        var securityKey = GetSecurityKey(services).GetAwaiter().GetResult();
        services.AddSingleton(securityKey);

        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IBearerTokenHandlingService, BearerTokenHandlingService>();

        services
            .AddAuthentication(Scheme.Bearer)
            .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
                Scheme.Bearer,
                options => options = bearerTokenAuthenticationOptions);

        return services;
    }

    private static async Task<SecurityKey> GetSecurityKey(IServiceCollection services)
    {
        services.AddHttpClient();
        services.TryAddTransient<IPublicKeyProvider, PublicKeyProvider>();
        services.TryAddTransient<ISecurityKeyProvider, SecurityKeyNetworkProvider>();

        var serviceProvider = services.BuildServiceProvider();
        var securityKeyProvider =
            serviceProvider.GetService(typeof(ISecurityKeyProvider)) as ISecurityKeyProvider ??
            throw new InvalidOperationException("Security key provider cannot be resolved");

        return await securityKeyProvider.GetSecurityKey();
    }
}