using System.Net;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Responses;

namespace Shark.AuthorizationServer.Controllers;

[Route("[controller]")]
[ApiController]
public class RegisterController(IRegisterApplicationService registerApplicationService) : ControllerBase
{
    private readonly IRegisterApplicationService _registerApplicationService = registerApplicationService;

    /// <summary>
    /// Dynamically register clients
    /// </summary>
    /// <param name="request">Register request</param>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Post([FromForm] RegisterRequest request)
    {
        var internalRequest = new RegisterInternalRequest
        {
            RedirectUris = request.redirect_uris,
            TokenEndpointAuthMethod = request.token_endpoint_auth_method,
            GrandTypes = request.grand_types,
            ResponseTypes = request.response_types,
            ClientName = request.client_name,
            ClientUri = request.client_uri,
            LogoUri = request.logo_uri,
            Scope = request.scope,
            Audience = request.audience,
        };

        var internalResponse = _registerApplicationService.Execute(internalRequest);

        switch (internalResponse)
        {
            case RegisterInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case RegisterInternalResponse response:
                return Ok(response);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}