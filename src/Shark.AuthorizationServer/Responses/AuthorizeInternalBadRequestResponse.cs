﻿namespace Shark.AuthorizationServer.Responses;

public sealed class AuthorizeInternalBadRequestResponse(string message) : AuthorizeInternalBaseResponse
{
    public string Message { get; init; } = message;
}