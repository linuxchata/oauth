﻿namespace Shark.AuthorizationServer.Responses;

public sealed class TokenInternalBadRequestResponse(string message) : TokenInternalBaseResponse
{
    public string Message { get; init; } = message;
}