using System.Net;
using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Requests;
using Shark.AuthorizationServer.Core.Responses.Authorize;

namespace Shark.AuthorizationServer.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class AuthorizeController(
    IAuthorizeApplicationService applicationService,
    IHttpContextAccessor httpContextAccessor) : ControllerBase
{
    private readonly IAuthorizeApplicationService _applicationService = applicationService;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    /// <summary>
    /// Initiates the authorization process, allowing resource owners to grant access to
    /// their protected resources by authenticating and authorizing third-party applications.
    /// </summary>
    /// <param name="response_type">Resposne type.</param>
    /// <param name="client_id">Client identifier.</param>
    /// <param name="redirect_uri">Redirect URI.</param>
    /// <param name="scope">Scope.</param>
    /// <param name="state">State.</param>
    /// <param name="code_challenge">Code challenge.</param>
    /// <param name="code_challenge_method">Code challenge method.</param>
    /// <returns>HTTP response.</returns>
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

        var internalResponse = await _applicationService.Execute(internalRequest);

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
