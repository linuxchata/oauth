using System.Net;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Responses.DeviceAuthorize;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public sealed class DeviceAuthorizeController(
    IDeviceAuthorizeApplicationService deviceAuthorizeApplicationService) : ControllerBase
{
    private readonly IDeviceAuthorizeApplicationService _deviceAuthorizeApplicationService = deviceAuthorizeApplicationService;

    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([FromForm] DeviceAuthorizeRequest request)
    {
        var internalResponse = await _deviceAuthorizeApplicationService.Execute(request.ToInternalRequest());

        switch (internalResponse)
        {
            case DeviceAuthorizeResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}