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
    public IActionResult Get()
    {
        return Execute();
    }

    [Authorize(AuthenticationSchemes = Scheme.Bearer)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Post()
    {
        return Execute();
    }

    private IActionResult Execute()
    {
        var claimsPrincipal = HttpContext.User;

        var internalResponse = _userInfoApplicationService.Execute(claimsPrincipal);

        switch (internalResponse)
        {
            case UserInfoForbiddenResponse:
                return Forbid();
            case UserInfoResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}