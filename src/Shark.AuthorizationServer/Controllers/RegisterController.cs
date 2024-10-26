using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.Register;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class RegisterController(IRegisterApplicationService applicationService) : ControllerBase
{
    private readonly IRegisterApplicationService _applicationService = applicationService;

    /// <summary>
    /// Reads a registered client.
    /// </summary>
    /// <param name="clientId">Client identifier.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.ClientToken)]
    [HttpGet("{clientId}")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Read([FromRoute] string clientId)
    {
        var internalResponse = await _applicationService.ExecuteRead(clientId);

        switch (internalResponse)
        {
            case RegisterInternalNotFoundResponse:
                return Unauthorized();
            case RegisterInternalResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }

    /// <summary>
    /// Dynamically registers a client.
    /// </summary>
    /// <param name="request">Register request.</param>
    /// <returns>HTTP response.</returns>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Post([FromBody] RegisterRequest request)
    {
        var internalResponse = await _applicationService.ExecutePost(request.ToInternalRequest());

        switch (internalResponse)
        {
            case RegisterInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case RegisterInternalResponse response:
                return Created(response.RegistrationClientUri, response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }

    /// <summary>
    /// Updates a registered client.
    /// </summary>
    /// <param name="clientId">Client identifier.</param>
    /// <param name="request">Register update request.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.ClientToken)]
    [HttpPut("{clientId}")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put(string clientId, [FromBody] RegisterUpdateRequest request)
    {
        var internalResponse = await _applicationService.ExecutePut(clientId, request.ToInternalRequest());

        switch (internalResponse)
        {
            case RegisterInternalNotFoundResponse:
                return Unauthorized();
            case RegisterInternalResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }

    /// <summary>
    /// Deletes registered a client.
    /// </summary>
    /// <param name="clientId">Client identifier.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.ClientToken)]
    [HttpDelete("{clientId}")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete([FromRoute] string clientId)
    {
        var internalResponse = await _applicationService.ExecuteDelete(clientId);

        switch (internalResponse)
        {
            case RegisterInternalNotFoundResponse:
                return Unauthorized();
            case RegisterInternalNoContentResponse:
                return NoContent();
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}