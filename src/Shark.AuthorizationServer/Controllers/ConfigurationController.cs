using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;

namespace Shark.AuthorizationServer.Controllers;

[Route(".well-known/openid-configuration")]
[ApiController]
public class ConfigurationController(
    IConfigurationApplicationService applicationService) : ControllerBase
{
    private readonly IConfigurationApplicationService _applicationService = applicationService;

    /// <summary>
    /// Gets well known OpenID configuration.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ResponseCache(NoStore = true, Duration = 0, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> Get()
    {
        var internalResponse = await _applicationService.Get();
        return Ok(internalResponse);
    }

    /// <summary>
    /// Gets set of keys containing the public keys used to verify
    /// JSON Web Token (JWT) issued by the Authorization Server.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [HttpGet("jwks")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ResponseCache(NoStore = true, Duration = 0, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetJsonWebKeySet()
    {
        var internalResponse = await _applicationService.GetJsonWebKeySet();
        return Ok(internalResponse);
    }
}