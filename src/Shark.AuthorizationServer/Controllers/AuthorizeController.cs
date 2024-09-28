using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Requests;
using Shark.AuthorizationServer.Response;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthorizeController(
    IAuthorizeApplicationService authorizeApplicationService,
    IHttpContextAccessor httpContextAccessor) : ControllerBase
{
    private readonly IAuthorizeApplicationService _authorizeApplicationService = authorizeApplicationService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    [Authorize(AuthenticationSchemes = Scheme.Cookies)]
    [HttpGet]
    public IActionResult Get(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string? state,
        [FromQuery] string redirect_url,
        [FromQuery] string scope)
    {
        var internalRequest = new AuthorizeInternalRequest
        {
            ResponseType = response_type,
            ClientId = client_id,
            Scopes = scope?.Split(' ') ?? [],
            State = state,
            RedirectUrl = redirect_url,
        };

        var internalResponse = _authorizeApplicationService.Execute(internalRequest);

        switch (internalResponse)
        {
            case AuthorizeInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case AuthorizeInternalResponse response:
                _httpContextAccessor.HttpContext?.Response.Redirect(response.RedirectUrl);
                return new StatusCodeResult((int)HttpStatusCode.Redirect);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}
