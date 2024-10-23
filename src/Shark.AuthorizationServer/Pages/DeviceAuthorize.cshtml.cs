using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Shark.AuthorizationServer.Pages;

public sealed class DeviceAuthorizeModel : PageModel
{
    public string? UserCode { get; set; }

    public void OnGet()
    {
        UserCode = TempData["userCode"] as string;
    }

    public void OnPost()
    {
    }
}