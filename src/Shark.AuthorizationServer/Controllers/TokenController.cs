using System.Net;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public class TokenController(ITokenApplicationService tokenApplicationService) : ControllerBase
{
    private readonly ITokenApplicationService _tokenApplicationService = tokenApplicationService;

    [HttpPost]
    public IActionResult Post([FromForm] TokenRequest request)
    {
        var internalResponse = _tokenApplicationService.Execute(request.ToInternalRequest());

        return internalResponse switch
        {
            TokenInternalBadRequestResponse badRequestResponse => BadRequest(badRequestResponse.Message),
            TokenInternalResponse response => Ok(response.Response),
            _ => new StatusCodeResult((int)HttpStatusCode.NotImplemented),
        };
    }
}
