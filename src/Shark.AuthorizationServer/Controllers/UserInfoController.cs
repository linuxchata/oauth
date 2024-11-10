using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.UserInfo;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class UserInfoController(
    IUserInfoApplicationService applicationService) : ControllerBase
{
    private readonly IUserInfoApplicationService _applicationService = applicationService;

    /// <summary>
    /// Returns claims about the authenticated end-user.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Get()
    {
        return await Execute();
    }

    /// <summary>
    /// Returns claims about the authenticated end-user.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Post()
    {
        return await Execute();
    }

    private async Task<IActionResult> Execute()
    {
        var userIdentity = HttpContext.User;
        var internalResponse = await _applicationService.Execute(userIdentity);

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