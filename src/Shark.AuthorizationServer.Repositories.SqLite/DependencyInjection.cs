using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public static class DependencyInjection
{
    public static IServiceCollection AddSqLiteDataStore(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SqLiteConfiguration>(configuration.GetSection(SqLiteConfiguration.Name));

        services.AddSingleton<IClientRepository, ClientRepository>();
        services.AddSingleton<IPersistedGrantRepository, PersistedGrantRepository>();
        services.AddSingleton<IRevokeTokenRepository, RevokeTokenRepository>();
        services.AddSingleton<IDevicePersistedGrantRepository, DevicePersistedGrantRepository>();

        return services;
    }
}