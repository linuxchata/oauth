﻿using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface IAuthorizationService
{
    string BuildLoginPageUrl(string responseType, string? state);

    Task<SecureToken> RequestAccessToken(string code, string? scope, string? actualState, string? expectedState);

    Task<SecureToken> RequestAccessToken(string refreshToken, string? scope);

    Task<SecureToken> RequestAccessToken(string? scope);
}