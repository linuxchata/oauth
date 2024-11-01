﻿namespace Shark.AuthorizationServer.Common.Constants;

public static class Scheme
{
    public const string Cookies = "authserver";

    public const string Basic = nameof(Basic);

    public const string ClientToken = nameof(ClientToken);

    public const string Bearer = nameof(Bearer);
}