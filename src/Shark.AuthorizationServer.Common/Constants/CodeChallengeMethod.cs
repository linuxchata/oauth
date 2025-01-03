﻿using System.Collections.Immutable;

namespace Shark.AuthorizationServer.Common.Constants;

public static class CodeChallengeMethod
{
    public const string Plain = "plain";

    public const string Sha256 = "S256";

    public readonly static ImmutableHashSet<string> Supported =
    [
        Plain,
        Sha256,
    ];
}