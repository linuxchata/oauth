using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class IntrospectController(
    IIntrospectApplicationService introspectApplicationService) : ControllerBase
{
    private readonly IIntrospectApplicationService _introspectApplicationService = introspectApplicationService;

    [HttpPost]
    public IActionResult Post([FromForm] IntrospectRequest request)
    {
        var internalRequest = new IntrospectInternalRequest
        {
            Token = request.Token,
        };

        var internalResponse = _introspectApplicationService.Execute(internalRequest);

        return Ok(internalResponse);
    }
}