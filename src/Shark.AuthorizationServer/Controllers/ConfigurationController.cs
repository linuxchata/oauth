using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.Abstractions.ApplicationServices;

namespace Shark.AuthorizationServer.Controllers;

[Route(".well-known/openid-configuration")]
[ApiController]
public class ConfigurationController(
    IConfigurationApplicationService configurationApplicationService) : ControllerBase
{
    private readonly IConfigurationApplicationService _configurationApplicationService = configurationApplicationService;

    /// <summary>
    /// Gets well known OpenID configuration.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Get()
    {
        var response = _configurationApplicationService.Get();
        return Ok(response);
    }

    /// <summary>
    /// Gets set of keys containing the public keys used to verify
    /// JSON Web Token (JWT) issued by the Authorization Server.
    /// </summary>
    /// <returns>HTTP response.</returns>
    [HttpGet("jwks")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetJsonWebKeySet()
    {
        var response = _configurationApplicationService.GetJsonWebKeySet();
        return Ok(response);
    }
}