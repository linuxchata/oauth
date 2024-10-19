using Shark.AuthorizationServer.Authentication;
using Shark.AuthorizationServer.Client.Extensions;
using Shark.AuthorizationServer.Client.Services;
using Shark.AuthorizationServer.Configurations;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Services;

namespace Shark.AuthorizationServer.Extensions;

public static class ApplicationBuilderExtentions
{
    public static IServiceCollection AddCustomAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var rsaSecurityKey = Rsa256KeysGenerator.GetRsaSecurityKey();
        services.AddSingleton(rsaSecurityKey);

        services.Configure<AuthorizationServerConfiguration>(
            configuration.GetSection(AuthorizationServerConfiguration.Name));

        var authorizationServerConfiguration = new AuthorizationServerConfiguration();
        configuration.GetSection(AuthorizationServerConfiguration.Name).Bind(authorizationServerConfiguration);

        var basicAuthenticationOptions = new BasicAuthenticationOptions();
        configuration.GetSection(BasicAuthenticationOptions.Name).Bind(basicAuthenticationOptions);

        var clientTokenAuthenticationOptions = new ClientTokenAuthenticationOptions();
        configuration.GetSection(ClientTokenAuthenticationOptions.Name).Bind(clientTokenAuthenticationOptions);

        // Authentication session.
        // Previously, the Cookies scheme was used to protect the /authorize endpoint.
        // However, this approach does not support non-browser-based flows.
        services
            .AddAuthentication(Scheme.Cookies)
            .AddCookie();

        // Basic authentication.
        services
            .AddAuthentication(Scheme.Basic)
            .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(
                Scheme.Basic,
                options => options = basicAuthenticationOptions);

        // Client registration authentication.
        services
            .AddAuthentication(Scheme.ClientToken)
            .AddScheme<ClientTokenAuthenticationOptions, ClientTokenAuthenticationHandler>(
                Scheme.ClientToken,
                options => options = clientTokenAuthenticationOptions);

        // Bearer token authentication.
        services.AddTransient<IRsaSecurityKeyProvider, RsaSecurityKeyLocalProvider>();
        services.AddSharkAuthentication(configuration);

        return services;
    }
}