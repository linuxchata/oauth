using Shark.Sample.Client.ApplicationServices;
using Microsoft.AspNetCore.Mvc;

namespace Shark.Sample.Client.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class CallbackController(
    ICallBackApplicationService callBackApplicationService) : ControllerBase
{
    private readonly ICallBackApplicationService _callBackApplicationService = callBackApplicationService;

    [HttpGet]
    public async Task<IActionResult> Callback(
        [FromQuery] string? code,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? access_token,
        [FromQuery] string? token_type)
    {
        await _callBackApplicationService.Execute(access_token, token_type, code, scope, state);

        return RedirectToPage("/Index");
    }
}
