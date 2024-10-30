using Shark.AuthorizationServer.Common.Extensions;

namespace Shark.AuthorizationServer.Middleware;
public class DisableTrackMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next;

    public async Task Invoke(HttpContext context)
    {
        if (context.Request.Method.EqualsTo("TRACE") ||
            context.Request.Method.EqualsTo("OPTIONS"))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            await context.Response.WriteAsync("Method Not Allowed");
            return;
        }

        await _next(context);
    }
}
