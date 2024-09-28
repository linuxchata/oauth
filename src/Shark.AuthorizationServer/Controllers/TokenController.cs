using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public class TokenController(
    ITokenApplicationService tokenApplicationService) : ControllerBase
{
    private readonly ITokenApplicationService _tokenApplicationService = tokenApplicationService;

    [Authorize(AuthenticationSchemes = Scheme.Basic)]
    [HttpPost]
    public IActionResult Post([FromForm] TokenRequest request)
    {
        var internalResponse = _tokenApplicationService.Execute(request.ToInternalRequest());

        switch (internalResponse)
        {
            case TokenInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case TokenInternalResponse response:
                return Ok(response.Response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}
