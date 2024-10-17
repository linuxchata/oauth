using Microsoft.Extensions.DependencyInjection;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Services;

namespace Shark.AuthorizationServer.DomainServices;

public static class DependencyInjection
{
    public static IServiceCollection RegisterDomainServices(this IServiceCollection services)
    {
        services.AddTransient<IStringGeneratorService, StringGeneratorService>();
        services.AddTransient<ISigningCredentialsService, SigningCredentialsService>();
        services.AddTransient<IAccessTokenGeneratorService, AccessTokenGeneratorService>();
        services.AddTransient<IIdTokenGeneratorService, IdTokenGeneratorService>();
        services.AddTransient<IProofKeyForCodeExchangeService, ProofKeyForCodeExchangeService>();
        services.AddTransient<ILoginService, LoginService>();
        services.AddTransient<IResourceOwnerCredentialsValidationService, ResourceOwnerCredentialsValidationService>();
        services.AddTransient<IRedirectionService, RedirectionService>();

        return services;
    }
}