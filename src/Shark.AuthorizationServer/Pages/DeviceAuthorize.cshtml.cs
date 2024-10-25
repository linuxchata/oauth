using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Core.Abstractions.Services;

namespace Shark.AuthorizationServer.Pages;

public sealed class DeviceAuthorizeModel(IDeviceService deviceService) : PageModel
{
    private const string UserCodeData = nameof(UserCodeData);
    private const string SuccessData = nameof(SuccessData);

    private readonly IDeviceService _deviceService = deviceService;

    public async Task<IActionResult> OnPostAuthorize()
    {
        await _deviceService.Authorize(GetUserCode());

        TempData[SuccessData] = true;
        return RedirectToPage("DeviceAuthorizeComplete");
    }

    public async Task<IActionResult> OnPostDeny()
    {
        await _deviceService.Deny(GetUserCode());

        TempData[SuccessData] = false;
        return RedirectToPage("DeviceAuthorizeComplete");
    }

    private string? GetUserCode()
    {
        var userCode = TempData[UserCodeData] as string;
        TempData[UserCodeData] = null;

        return userCode;
    }
}