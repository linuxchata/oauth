using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Shark.AuthorizationServer.Core.Abstractions.Services;

namespace Shark.Sample.AuthorizationServer.Pages.Device;

public sealed class DeviceModel(IDeviceService deviceService) : PageModel
{
    private const string UserCodeData = nameof(UserCodeData);

    private readonly IDeviceService _deviceService = deviceService;

    [Required]
    public string? UserCode { get; set; }

    public async Task<IActionResult> OnGet([FromQuery(Name = "user_code")] string userCode)
    {
        if (!string.IsNullOrEmpty(userCode))
        {
            return await RedirectToDeviceAuthorizePage(userCode);
        }

        return Page();
    }

    public async Task<IActionResult> OnPost(string userCode)
    {
        if (ModelState.IsValid)
        {
            if (!string.IsNullOrEmpty(userCode))
            {
                return await RedirectToDeviceAuthorizePage(userCode);
            }
        }

        return RedirectToPage("Error");
    }

    private async Task<IActionResult> RedirectToDeviceAuthorizePage(string userCode)
    {
        if (await _deviceService.ValidateUserCode(userCode))
        {
            TempData[UserCodeData] = userCode;
            return RedirectToPage("DeviceAuthorize");
        }

        ModelState.AddModelError("UserCode", "Invalid code");

        return Page();
    }
}