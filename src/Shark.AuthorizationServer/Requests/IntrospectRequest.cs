﻿namespace Shark.AuthorizationServer.Requests;

public sealed class IntrospectRequest
{
    public required string token { get; set; }
}