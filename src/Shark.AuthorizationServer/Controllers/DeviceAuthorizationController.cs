﻿using System.Net;
using System.Net.Mime;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public sealed class DeviceAuthorizationController(
    IDeviceAuthorizationApplicationService applicationService) : ControllerBase
{
    private readonly IDeviceAuthorizationApplicationService _applicationService = applicationService;

    /// <summary>
    /// Used by the client to obtain a device and user code that the user can
    /// enter on a separate device to grant authorization.
    /// </summary>
    /// <param name="request">Device authorization request.</param>
    /// <returns>HTTP response.</returns>
    [HttpPost]
    [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<IActionResult> Post([FromForm] DeviceAuthorizationRequest request)
    {
        var internalResponse = await _applicationService.Execute(request.ToInternalRequest());

        switch (internalResponse)
        {
            case DeviceAuthorizationBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case DeviceAuthorizationResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}