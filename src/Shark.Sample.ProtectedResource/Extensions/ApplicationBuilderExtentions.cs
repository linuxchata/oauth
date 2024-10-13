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
}