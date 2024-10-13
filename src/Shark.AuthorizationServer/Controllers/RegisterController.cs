using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class RegisterController(IRegisterApplicationService registerApplicationService) : ControllerBase
{
    private readonly IRegisterApplicationService _registerApplicationService = registerApplicationService;

    /// <summary>
    /// Reads a register client.
    /// </summary>
    /// <param name="clientId">Client identifier.</param>
    /// <returns>HTTP response.</returns>
    [HttpGet("{clientId}")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Read([FromRoute] string clientId)
    {
        var internalResponse = _registerApplicationService.Read(clientId);

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
    public IActionResult Post([FromBody] RegisterRequest request)
    {
        var internalResponse = _registerApplicationService.Post(request.ToInternalRequest());

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
    /// Deletes register a client.
    /// </summary>
    /// <param name="clientId">Client identifier.</param>
    /// <returns>HTTP response.</returns>
    [HttpDelete("{clientId}")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public IActionResult Delete([FromRoute] string clientId)
    {
        var internalResponse = _registerApplicationService.Delete(clientId);

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