using System.Text;
using Microsoft.IdentityModel.Tokens;
using Shark.AuthorizationServer.Authentication;
using Shark.AuthorizationServer.Client.Extensions;
using Shark.AuthorizationServer.Client.Services;
using Shark.AuthorizationServer.Configurations;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.DomainServices.Services;

namespace Shark.AuthorizationServer.Extensions;

public static class ApplicationBuilderExtentions
{
    private const string Public = "public";
    private const string Private = "private";

    public static IServiceCollection AddCustomAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

        services.AddSecurityKey(configuration);

        services.Configure<AuthorizationServerConfiguration>(
            configuration.GetSection(AuthorizationServerConfiguration.Name));

        services.Configure<AuthorizationServerSecurityConfiguration>(
            configuration.GetSection(AuthorizationServerSecurityConfiguration.Name));

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
        services.AddTransient<ISecurityKeyProvider, SecurityKeyLocalProvider>();
        services.AddSharkAuthentication(configuration);

        return services;
    }

    private static void AddSecurityKey(this IServiceCollection services, IConfiguration configuration)
    {
        var securityConfiguration = new AuthorizationServerSecurityConfiguration();
        configuration.GetSection(AuthorizationServerSecurityConfiguration.Name).Bind(securityConfiguration);

        if (securityConfiguration.SecurityAlgorithms == SecurityAlgorithms.HmacSha256)
        {
            var key = Encoding.UTF8.GetBytes(securityConfiguration.SymmetricSecurityKey!);
            var symmetricSecurityKey = new SymmetricSecurityKey(key);

            services.AddSingleton(symmetricSecurityKey);
        }
        else if (securityConfiguration.SecurityAlgorithms == SecurityAlgorithms.RsaSha256)
        {
            if (securityConfiguration.UseRsaCertificate)
            {
                var publicX509SecurityKey = SecurityKeyProvider.GetFromPublicCertificate(
                    securityConfiguration.PublicCertificatePath!);
                var privateX509SecurityKey = SecurityKeyProvider.GetFromPrivateCertificate(
                    securityConfiguration.PrivateCertificatePath!, securityConfiguration.PrivateCertificatePassword!);
                var signingCertificate = SigningCertificateProvider.Get(securityConfiguration.PublicCertificatePath!);

                services.AddKeyedSingleton(Public, publicX509SecurityKey);
                services.AddKeyedSingleton(Private, privateX509SecurityKey);
                services.AddTransient(s => signingCertificate);
            }
            else
            {
                var publicRsaSecurityKey = SecurityKeyProvider.GetFromPublicKey(
                    securityConfiguration.PublicKeyPath!);
                var privateRsaSecurityKey = SecurityKeyProvider.GetFromPrivateKey(
                    securityConfiguration.PrivateKeyPath!);

                services.AddKeyedSingleton(Public, publicRsaSecurityKey);
                services.AddKeyedSingleton(Private, privateRsaSecurityKey);
                services.AddTransient(s => new SigningCertificate());
            }
        }
    }
}