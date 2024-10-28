using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Abstractions.Stores;
using Shark.AuthorizationServer.Sdk.Authentication;
using Shark.AuthorizationServer.Sdk.Constants;
using Shark.AuthorizationServer.Sdk.Models;
using Shark.AuthorizationServer.Sdk.Services;
using Shark.AuthorizationServer.Sdk.Stores;

namespace Shark.AuthorizationServer.Sdk.Extensions;

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

    public static IServiceCollection AddSharkClient(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<AuthorizationServerConfiguration>(
            configuration.GetSection(AuthorizationServerConfiguration.Name));

        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        services.AddDistributedMemoryCache();

        services.AddSingleton<IStateStore, StateStore>();
        services.AddSingleton<ISecureTokenStore, SecureTokenStore>();

        services.AddTransient<IStringGeneratorService, StringGeneratorService>();
        services.AddTransient<IProofKeyForCodeExchangeService, ProofKeyForCodeExchangeService>();
        services.AddTransient<IClientAuthorizationService, ClientAuthorizationService>();
        services.AddTransient<IClientAccessTokenService, ClientAccessTokenService>();
        services.AddTransient<ICallBackService, CallBackService>();

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