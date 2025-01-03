﻿namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IStringGeneratorService
{
    string GenerateCode(byte length = 40);

    string GenerateRefreshToken(byte length = 64);

    string GenerateClientSecret(byte length = 18);

    string GenerateClientAccessToken(byte length = 42);

    string GenerateDeviceCode(byte length = 47);

    string GenerateUserDeviceCode(byte length = 6);
}