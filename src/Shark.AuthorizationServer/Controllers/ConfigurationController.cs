using Microsoft.AspNetCore.Mvc;
using Shark.AuthorizationServer.ApplicationServices;

namespace Shark.AuthorizationServer.Controllers;

[Route(".well-known/openid-configuration")]
[ApiController]
public class ConfigurationController : ControllerBase
{
    private readonly IConfigurationApplicationService _configurationApplicationService;

    public ConfigurationController(IConfigurationApplicationService configurationApplicationService)
    {
        _configurationApplicationService = configurationApplicationService;
    }

    [HttpGet]
    public IActionResult Get()
    {
        var request = HttpContext.Request;
        var response = _configurationApplicationService.Get(
            request.Scheme,
            request.Host.Host.ToString(),
            request.Host.Port ?? 443);
        return Ok(response);
    }
}