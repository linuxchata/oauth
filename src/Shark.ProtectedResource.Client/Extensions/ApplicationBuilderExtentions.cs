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
        services.AddTransient<IRsaSecurityKeyProvider, RsaSecurityKeyProvider>();

        var serviceProvider = services.BuildServiceProvider();
        var rsaSecurityKeyProvider =
            serviceProvider.GetService(typeof(IRsaSecurityKeyProvider)) as IRsaSecurityKeyProvider ??
            throw new InvalidOperationException("RSA Security Key provider cannot be resolved");

        return await rsaSecurityKeyProvider.GetRsaSecurityKey();
    }
}