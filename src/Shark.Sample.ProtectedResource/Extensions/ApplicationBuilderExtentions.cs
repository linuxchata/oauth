using Shark.Sample.ProtectedResource.Authentication;
using Shark.Sample.ProtectedResource.Constants;
using Shark.Sample.ProtectedResource.Models;
using Shark.Sample.ProtectedResource.Services;

namespace Shark.Sample.ProtectedResource.Extensions;

public static class ApplicationBuilderExtentions
{
    public static IApplicationBuilder UseNoSniffHeaders(this IApplicationBuilder builder)
    {
        return builder.Use(async (context, next) =>
        {
            context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
            await next();
        });
    }

    public static IServiceCollection AddAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<BearerTokenAuthenticationOptions>(
        configuration.GetSection(BearerTokenAuthenticationOptions.Name));

        var bearerTokenAuthenticationOptions = new BearerTokenAuthenticationOptions();
        configuration.GetSection(BearerTokenAuthenticationOptions.Name).Bind(bearerTokenAuthenticationOptions);

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
}