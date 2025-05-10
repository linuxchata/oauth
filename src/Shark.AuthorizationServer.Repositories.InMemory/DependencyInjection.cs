using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;

namespace Shark.AuthorizationServer.Repositories.InMemory;

public static class DependencyInjection
{
    public static IServiceCollection AddInMemoryDataStore(this IServiceCollection services)
    {
        services.AddDistributedMemoryCache();

        services.AddSingleton<IClientRepository, ClientRepository>();
        services.AddSingleton<IPersistedGrantRepository, PersistedGrantRepository>();
        services.AddSingleton<IRevokeTokenRepository, RevokeTokenRepository>();
        services.AddSingleton<IDevicePersistedGrantRepository, DevicePersistedGrantRepository>();

        services.AddSingleton<IMockClientsLoader, MockClientsLoader>();

        return services;
    }

    public static IApplicationBuilder UseMockClients(this IApplicationBuilder builder)
    {
        var mockClientsLoader = builder.ApplicationServices.GetService<IMockClientsLoader>();
        mockClientsLoader?.Load();

        return builder;
    }
}