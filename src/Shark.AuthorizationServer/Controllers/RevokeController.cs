using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.Revoke;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class RevokeController(IRevokeApplicationService _applicationService) : ControllerBase
{
    private readonly IRevokeApplicationService _applicationService = _applicationService;

    /// <summary>
    /// Invalidates the actual token and, if applicable, other tokens based
    /// on the same authorization grant and the authorization grant itself.
    /// </summary>
    /// <param name="request">Revocation request.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.Basic, Policy = Policy.Strict)]
    [HttpPost]
    [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([FromForm] RevokeRequest request)
    {
        var internalResponse = await _applicationService.Execute(request.ToInternalRequest());

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