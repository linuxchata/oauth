using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.UserInfo;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class UserInfoController(
    IUserInfoApplicationService userInfoApplicationService) : ControllerBase
{
    private readonly IUserInfoApplicationService _userInfoApplicationService = userInfoApplicationService;

    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Get()
    {
        return await Execute();
    }

    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post()
    {
        return await Execute();
    }

    private async Task<IActionResult> Execute()
    {
        var claimsPrincipal = HttpContext.User;

        var internalResponse = await _userInfoApplicationService.Execute(claimsPrincipal);

        switch (internalResponse)
        {
            case UserInfoForbiddenResponse:
                return Forbid();
            case UserInfoBadRequestResponse:
                return BadRequest();
            case UserInfoResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}