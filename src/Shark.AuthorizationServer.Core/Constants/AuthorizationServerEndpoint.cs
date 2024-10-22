namespace Shark.AuthorizationServer.Core.Constants;

public static class AuthorizationServerEndpoint
{
    public const string Authorize = "authorize";

    public const string Token = "token";

    public const string Introspect = "introspect";

    public const string Revoke = "revoke";

    public const string Register = "register";

    public const string UserInfo = "userinfo";

    public const string DeviceAuthorization = "deviceauthorization";

    public const string ConfigurationJwks = ".well-known/openid-configuration/jwks";
}