namespace Shark.AuthorizationServer.Common.Constants;

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