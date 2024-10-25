﻿using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class ResourceOwnerCredentialsValidationService : IResourceOwnerCredentialsValidationService
{
    public bool ValidateCredentials(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        return true;
    }
}