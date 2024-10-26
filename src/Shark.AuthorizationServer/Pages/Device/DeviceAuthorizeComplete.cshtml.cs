using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Shark.AuthorizationServer.Pages.Device;

public sealed class DeviceAuthorizeCompleteModel : PageModel
{
    private const string SuccessData = nameof(SuccessData);

    public bool Success { get; private set; }

    public void OnGet()
    {
        Success = Convert.ToBoolean(TempData[SuccessData]);
    }
}