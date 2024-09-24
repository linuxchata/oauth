using Microsoft.AspNetCore.Mvc;
using Shark.Sample.ProtectedResource.Services;

namespace Shark.Sample.ProtectedResource.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Get()
    {
        if (!AuthenticationService.IsAuthenticated(Request.Headers))
        {
            return new StatusCodeResult((int)StatusCodes.Status401Unauthorized);
        }

        var result = Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-35, 40),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        });

        return Ok(result.ToArray());
    }
}
