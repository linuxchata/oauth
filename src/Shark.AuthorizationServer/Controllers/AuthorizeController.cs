using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class AuthorizeController(
    IAuthorizeApplicationService authorizeApplicationService,
    IHttpContextAccessor httpContextAccessor) : ControllerBase
{
    private readonly IAuthorizeApplicationService _authorizeApplicationService = authorizeApplicationService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    [Authorize(AuthenticationSchemes = Scheme.Cookies)]
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status302Found)]
    public async Task<IActionResult> Get(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery] string? code_challenge,
        [FromQuery] string? code_challenge_method)
    {
        var internalRequest = new AuthorizeInternalRequest
        {
            ResponseType = response_type,
            ClientId = client_id,
            RedirectUri = redirect_uri,
            Scopes = scope?.Split(' ') ?? [],
            State = state,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method,
        };

        var internalResponse = await _authorizeApplicationService.Execute(internalRequest);

        switch (internalResponse)
        {
            case AuthorizeInternalBadRequestResponse badRequestResponse:
                return BadRequest(badRequestResponse.Message);
            case AuthorizeInternalCodeResponse response:
                _httpContextAccessor.HttpContext?.Response.Redirect(response.RedirectUrl);
                return new StatusCodeResult((int)HttpStatusCode.Redirect);
            case AuthorizeInternalTokenResponse response:
                _httpContextAccessor.HttpContext?.Response.Redirect(response.RedirectUrl);
                return new StatusCodeResult((int)HttpStatusCode.Redirect);
            default:
                return new StatusCodeResult((int)HttpStatusCode.NotImplemented);
        }
    }
}
