namespace Shark.AuthorizationServer.Core.Abstractions.Services;

public interface IDeviceService
{
    Task<bool> ValidateUserCode(string? userCode);

    Task Authorize(string? userCode);

    Task Deny(string? userCode);
}
