using System.Net;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthorizeController(IAuthorizeApplicationService authorizeApplicationService) : ControllerBase
{
    private readonly IAuthorizeApplicationService _authorizeApplicationService = authorizeApplicationService;

    [HttpGet]
    public IActionResult Get(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_url,
        [FromQuery] string state)
    {
        var internalResponse = _authorizeApplicationService.Execute(client_id, redirect_url);

        return internalResponse switch
        {
            AuthorizeInternalBadRequestResponse badRequestResponse => BadRequest(badRequestResponse.Message),
            AuthorizeInternalResponse response => RedirectToPage(
                "/Login",
                new
                {
                    clientId = client_id,
                    code = response.Code,
                    redirectBaseUrl = redirect_url,
                    state = state,
                }),
            _ => new StatusCodeResult((int)HttpStatusCode.NotImplemented),
        };
    }
}
