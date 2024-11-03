namespace Shark.Sample.AuthorizationServer.Middlewares;

public class DisableTrackMiddleware(RequestDelegate next)
{
    private readonly RequestDelegate _next = next;

    public async Task Invoke(HttpContext context)
    {
        if (string.Equals(context.Request.Method, "TRACE", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.Request.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }

        await _next(context);
    }
}
