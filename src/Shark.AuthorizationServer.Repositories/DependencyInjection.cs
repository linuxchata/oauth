using Microsoft.Extensions.DependencyInjection;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;

namespace Shark.AuthorizationServer.Repositories;

public static class DependencyInjection
{
    public static IServiceCollection RegisterRepositories(this IServiceCollection services)
    {
        services.AddSingleton<IClientRepository, ClientRepository>();
        services.AddSingleton<IPersistedGrantRepository, PersistedGrantRepository>();
        services.AddSingleton<IRevokeTokenRepository, RevokeTokenRepository>();

        return services;
    }
}