using System.Collections.Immutable;

namespace Shark.AuthorizationServer.Common.Constants;

public static class ResponseType
{
    public const string Code = "code";

    public const string Token = "token";

    public readonly static ImmutableHashSet<string> Supported =
    [
        Code,
        Token,
    ];
}