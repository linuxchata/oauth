using Microsoft.Extensions.DependencyInjection;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.ApplicationServices;

namespace Shark.AuthorizationServer.Core;

public static class DependencyInjection
{
    public static IServiceCollection RegisterApplicationServices(this IServiceCollection services)
    {
        services.AddTransient<IAuthorizeApplicationService, AuthorizeApplicationService>();
        services.AddTransient<ITokenApplicationService, TokenApplicationService>();
        services.AddTransient<IIntrospectApplicationService, IntrospectApplicationService>();
        services.AddTransient<IRevokeApplicationService, RevokeApplicationService>();
        services.AddTransient<IConfigurationApplicationService, ConfigurationApplicationService>();
        services.AddTransient<IRegisterApplicationService, RegisterApplicationService>();
        services.AddTransient<IUserInfoApplicationService, UserInfoApplicationService>();
        services.AddTransient<IDeviceAuthorizationApplicationService, DeviceAuthorizationApplicationService>();

        return services;
    }
}