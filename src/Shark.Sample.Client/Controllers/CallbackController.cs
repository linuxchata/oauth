using Shark.Sample.Client.ApplicationServices;
using Microsoft.AspNetCore.Mvc;

namespace Shark.Sample.Client.Controllers;

[ApiController]
[Route("[controller]")]
public class CallbackController(
    ICallBackApplicationService callBackApplicationService) : ControllerBase
{
    private readonly ICallBackApplicationService _callBackApplicationService = callBackApplicationService;

    [HttpGet]
    public async Task<IActionResult> Callback(
        [FromQuery] string code,
        [FromQuery] string? scope,
        [FromQuery] string? state)
    {
        await _callBackApplicationService.Execute(code, scope, state);

        return RedirectToPage("/Index");
    }
}
