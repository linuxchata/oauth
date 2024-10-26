using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.UserInfo;
using Shark.AuthorizationServer.Sdk.Constants;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class UserInfoController(
    IUserInfoApplicationService applicationService) : ControllerBase
{
    private readonly IUserInfoApplicationService _applicationService = applicationService;

    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Get()
    {
        return await Execute();
    }

    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post()
    {
        return await Execute();
    }

    private async Task<IActionResult> Execute()
    {
        var internalResponse = await _applicationService.Execute(HttpContext.User);

        switch (internalResponse)
        {
            case UserInfoForbiddenResponse:
                return Forbid();
            case UserInfoBadRequestResponse:
                return BadRequest();
            case UserInfoNotFoundResponse:
                return NotFound();
            case UserInfoResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}