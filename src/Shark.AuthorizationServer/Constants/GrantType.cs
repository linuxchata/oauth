﻿namespace Shark.AuthorizationServer.Constants;

public sealed class GrantType
{
    public const string AuthorizationCode = "authorization_code";

    public const string Implicit = "implicit";

    public const string RefreshToken = "refresh_token";

    public const string ClientCredentials = "client_credentials";
}