using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Mappers;
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
    /// <param name="request">Introspect request.</param>
    /// <returns>HTTP response.</returns>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([FromForm] IntrospectRequest request)
    {
        var internalResponse = await _introspectApplicationService.Execute(request.ToInternalRequest());

        return Ok(internalResponse);
    }
}