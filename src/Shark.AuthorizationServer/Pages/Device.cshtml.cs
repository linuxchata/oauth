using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Shark.AuthorizationServer.Pages;

public sealed class DeviceModel : PageModel
{
    public string? UserCode { get; set; }

    public IActionResult OnGet([FromQuery(Name = "user_code")] string userCode)
    {
        if (!string.IsNullOrEmpty(userCode))
        {
            TempData["userCode"] = userCode;
            return RedirectToPage("DeviceAuthorize");
        }

        return Page();
    }

    public IActionResult OnPost(string userCode)
    {
        TempData["userCode"] = userCode;
        return RedirectToPage("DeviceAuthorize");
    }
}