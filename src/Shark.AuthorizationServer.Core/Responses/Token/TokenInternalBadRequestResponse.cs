﻿namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalBadRequestResponse(string message) : TokenInternalBaseResponse
{
    public string Message { get; init; } = message;
}