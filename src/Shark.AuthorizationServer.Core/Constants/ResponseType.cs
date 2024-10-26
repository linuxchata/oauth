namespace Shark.AuthorizationServer.Core.Constants;

public static class ResponseType
{
    public const string Code = "code";

    public const string Token = "token";

    public readonly static string[] SupportedResponseTypes =
    [
        ResponseType.Code,
        ResponseType.Token,
    ];
}