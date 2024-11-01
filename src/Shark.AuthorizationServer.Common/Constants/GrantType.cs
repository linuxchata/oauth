namespace Shark.AuthorizationServer.Common.Constants;

public static class GrantType
{
    public const string AuthorizationCode = "authorization_code";

    public const string RefreshToken = "refresh_token";

    public const string Implicit = "implicit";

    public const string ClientCredentials = "client_credentials";

    public const string ResourceOwnerCredentials = "password";

    public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";

    public readonly static HashSet<string> Allowed =
    [
        AuthorizationCode,
        RefreshToken,
        Implicit,
        ResourceOwnerCredentials,
        ClientCredentials,
        DeviceCode,
    ];

    public readonly static string[] Supported =
    [
        AuthorizationCode,
        RefreshToken,
        Implicit,
        ClientCredentials,
        ResourceOwnerCredentials,
        DeviceCode
    ];
}