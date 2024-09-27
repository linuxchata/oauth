namespace Shark.AuthorizationServer.Helpers;

public static class UrlHelper
{
    public static string GetUri(this HttpRequest httpRequest)
    {
        var scheme = httpRequest.Scheme;
        var hostUrl = httpRequest.Host.Host;
        var port = httpRequest.Host.Port;

        var uriBuilder = new UriBuilder
        {
            Scheme = scheme,
            Host = hostUrl,
        };

        if (port.HasValue)
        {
            uriBuilder.Port = port.Value;
        }

        return uriBuilder.ToString();
    }
}