﻿using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IClientAuthorizationService
{
    string BuildLoginPageUrl(string responseType, string state);

    string BuildLoginPageUrl(string responseType, string state, ProofKeyForCodeExchange pkce);

    string BuildLoginPageUrl(string responseType);
}