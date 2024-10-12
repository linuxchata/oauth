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
    /// Gets well known OpenID configuration
    /// </summary>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Get()
    {
        var request = HttpContext.Request;
        var response = _configurationApplicationService.Get(
            request.Scheme,
            request.Host.Host.ToString(),
            request.Host.Port ?? 443);
        return Ok(response);
    }

    /// <summary>
    /// Gets set of keys containing the public keys used to verify
    /// JSON Web Token (JWT) issued by the Authorization Server
    /// </summary>
    [HttpGet("jwks")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetJsonWebKeySet()
    {
        var response = _configurationApplicationService.GetJsonWebKeySet();
        return Ok(response);
    }
}