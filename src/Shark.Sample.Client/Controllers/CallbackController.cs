using Shark.Sample.Client.ApplicationServices;
using Microsoft.AspNetCore.Mvc;

namespace Shark.Sample.Client.Controllers;

[ApiController]
[Route("[controller]")]
public class CallbackController : ControllerBase
{
    private readonly ICallBackApplicationService _callBackApplicationService;
    private readonly ILogger<CallbackController> _logger;

    public CallbackController(
        ICallBackApplicationService callBackApplicationService,
        ILogger<CallbackController> logger)
    {
        _callBackApplicationService = callBackApplicationService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> Callback(
        [FromQuery] string code,
        [FromQuery] string scope,
        [FromQuery] string state)
    {
        await _callBackApplicationService.Execute(code, scope, state);

        return RedirectToPage("/Index");
    }
}
