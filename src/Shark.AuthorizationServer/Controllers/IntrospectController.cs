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

    /// <summary>
    /// Determine the active state of an OAuth 2.0 token and to determine meta-information about this token.
    /// </summary>
    /// <param name="request">Introspect request</param>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Post([FromForm] IntrospectRequest request)
    {
        var internalRequest = new IntrospectInternalRequest
        {
            Token = request.token,
        };

        var internalResponse = _introspectApplicationService.Execute(internalRequest);

        return Ok(internalResponse);
    }
}