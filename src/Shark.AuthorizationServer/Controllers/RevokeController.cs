using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class RevokeController(IRevokeApplicationService revokeApplicationService) : ControllerBase
{
    private readonly IRevokeApplicationService _revokeApplicationService = revokeApplicationService;

    /// <summary>
    /// Invalidates the actual token and, if applicable, other tokens based
    /// on the same authorization grant and the authorization grant itself.
    /// </summary>
    /// <param name="request">Revocation request.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.Basic)]
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Post([FromForm] RevokeRequest request)
    {
        var internalResponse = _revokeApplicationService.Execute(request.ToInternalRequest());

        switch (internalResponse)
        {
            case RevokeInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case RevokeInternalResponse:
                return Ok();
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}