﻿using System.ComponentModel;

namespace Shark.AuthorizationServer.Requests;

public sealed class TokenRequest
{
    public string? grant_type { get; set; }

    public string? code { get; set; }

    public string? code_verifier { get; set; }

    public string? redirect_uri { get; set; }

    public string? client_id { get; set; }

    public string? client_secret { get; set; }

    public string? scope { get; set; }

    public string? refresh_token { get; set; }

    [DefaultValue("")]
    public string? username { get; set; }

    [DefaultValue("")]
    public string? password { get; set; }

    [DefaultValue("")]
    public string? device_code { get; set; }
}
