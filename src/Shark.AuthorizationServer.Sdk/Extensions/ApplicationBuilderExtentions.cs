using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Polly;
using Polly.Retry;
using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.Common.Abstractions;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;
using Shark.AuthorizationServer.Sdk.Abstractions.Stores;
using Shark.AuthorizationServer.Sdk.Authentication;
using Shark.AuthorizationServer.Sdk.Configurations;
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

        var securityKey = GetSecurityKey(services, bearerTokenAuthenticationOptions).GetAwaiter().GetResult();
        services.AddSingleton(securityKey);

        services.AddTransient<ICustomAccessTokenHandler, CustomAccessTokenHandler>();
        services.AddTransient<ICertificateValidator, CertificateValidator>();
        services.AddTransient<IBearerTokenHandler, BearerTokenHandler>();

        services
            .AddAuthentication(Scheme.Bearer)
            .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
                Scheme.Bearer,
                options =>
                {
                    options.AuthorizationServerUri = bearerTokenAuthenticationOptions.AuthorizationServerUri;
                    options.Issuer = bearerTokenAuthenticationOptions.Issuer;
                    options.ValidateIssuer = bearerTokenAuthenticationOptions.ValidateIssuer;
                    options.Audience = bearerTokenAuthenticationOptions.Audience;
                    options.ValidateAudience = bearerTokenAuthenticationOptions.ValidateAudience;
                    options.TokenIntrospection = bearerTokenAuthenticationOptions.TokenIntrospection;
                    options.RetryConfiguration = bearerTokenAuthenticationOptions.RetryConfiguration;
                });

        return services;
    }

    public static IServiceCollection AddSharkClient(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AuthorizationConfiguration>(
            configuration.GetSection(AuthorizationConfiguration.Name));

        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        services.AddDistributedMemoryCache();

        services.AddSingleton<IStateStore, StateStore>();
        services.AddSingleton<ISecureTokenStore, SecureTokenStore>();

        services.AddTransient<IStringGeneratorService, StringGeneratorService>();
        services.AddTransient<IProofKeyForCodeExchangeService, ProofKeyForCodeExchangeService>();
        services.AddTransient<IAuthorizationClientService, AuthorizationClientService>();
        services.AddTransient<IAccessTokenClientInternalService, AccessTokenClientInternalService>();
        services.AddTransient<IAccessTokenClientService, AccessTokenClientService>();
        services.AddTransient<ICallBackClientService, CallBackClientService>();

        return services;
    }

    private static async Task<SecurityKey> GetSecurityKey(
        IServiceCollection services,
        BearerTokenAuthenticationOptions options)
    {
        services.AddHttpClient();

        AddConfigurationRetries(services, options);

        services.TryAddTransient<IConfigurationJwksProvider, ConfigurationJwksProvider>();
        services.TryAddTransient<IIntrospectionProvider, IntrospectionProvider>();
        services.TryAddTransient<ISecurityKeyProvider, SecurityKeyNetworkProvider>();

        var serviceProvider = services.BuildServiceProvider();
        var securityKeyProvider =
            serviceProvider.GetService(typeof(ISecurityKeyProvider)) as ISecurityKeyProvider ??
            throw new InvalidOperationException("Security key provider cannot be resolved");

        return await securityKeyProvider.GetSecurityKey();
    }

    private static void AddConfigurationRetries(IServiceCollection services, BearerTokenAuthenticationOptions options)
    {
        if (options.RetryConfiguration?.Enabled ?? false)
        {
            services.AddResiliencePipeline("configuration", builder =>
            {
                builder
                    .AddRetry(new RetryStrategyOptions
                    {
                        Delay = TimeSpan.FromSeconds(options.RetryConfiguration.DelayInSeconds),
                        MaxRetryAttempts = options.RetryConfiguration.MaxAttempts,
                    })
                    .AddTimeout(TimeSpan.FromSeconds(options.RetryConfiguration.TimeoutInSeconds));
            });
        }
    }
}