﻿using Microsoft.AspNetCore.Http;
using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public interface IBearerTokenHandlingService
{
    string? GetAccessToken(IHeaderDictionary headers);

    bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity);
}