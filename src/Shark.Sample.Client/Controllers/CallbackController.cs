using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Sdk.Abstractions.Services;

namespace Shark.Sample.Client.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class CallbackController(
    ICallBackClientService callBackService) : ControllerBase
{
    private readonly ICallBackClientService _callBackService = callBackService;

    [HttpGet]
    public async Task<IActionResult> Callback(
        [FromQuery] string? code,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? access_token,
        [FromQuery] string? token_type)
    {
        await _callBackService.Execute(access_token, token_type, code, scope, state);

        return RedirectToPage("/Index");
    }
}
