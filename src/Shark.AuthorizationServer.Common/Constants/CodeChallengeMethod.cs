namespace Shark.AuthorizationServer.Common.Constants;

public static class CodeChallengeMethod
{
    public const string Plain = "plain";

    public const string Sha256 = "S256";

    public readonly static HashSet<string> Supported =
    [
        Plain,
        Sha256,
    ];
}