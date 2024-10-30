using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.Token;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class TokenController(
    ITokenApplicationService applicationService) : ControllerBase
{
    private readonly ITokenApplicationService _applicationService = applicationService;

    [Authorize(AuthenticationSchemes = Scheme.Basic)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Post([FromForm] TokenRequest request)
    {
        var internalResponse = await _applicationService.Execute(request.ToInternalRequest(), HttpContext.User);

        switch (internalResponse)
        {
            case TokenInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case TokenInternalResponse response:
                return Ok(response.TokenResponse);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}
