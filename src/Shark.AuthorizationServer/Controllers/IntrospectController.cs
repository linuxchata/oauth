using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Mappers;
using Shark.AuthorizationServer.Requests;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class IntrospectController(
    IIntrospectApplicationService applicationService) : ControllerBase
{
    private readonly IIntrospectApplicationService _applicationService = applicationService;

    /// <summary>
    /// Determines the active state of an OAuth 2.0 token and determines meta-information about the token.
    /// </summary>
    /// <param name="request">Introspect request.</param>
    /// <returns>HTTP response.</returns>
    [Authorize(AuthenticationSchemes = Scheme.Basic, Policy = Policy.Strict)]
    [HttpPost]
    [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([FromForm] IntrospectRequest request)
    {
        var internalResponse = await _applicationService.Execute(request.ToInternalRequest(), HttpContext.User);

        return Ok(internalResponse);
    }
}