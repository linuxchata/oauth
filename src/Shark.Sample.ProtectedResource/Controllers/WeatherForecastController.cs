using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.Sample.ProtectedResource.Constants;
using Shark.Sample.ProtectedResource.Services;

namespace Shark.Sample.ProtectedResource.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    private readonly List<WeatherForecast> _forecast;

    private readonly IBearerTokenHandlingService _authenticationService;

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(
        IBearerTokenHandlingService authenticationService,
        ILogger<WeatherForecastController> logger)
    {
        _authenticationService = authenticationService;
        _logger = logger;

        _forecast = Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-35, 40),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        }).ToList();
    }

    [HttpGet]
    [Authorize(Scope.Read)]
    public IActionResult Get()
    {
        return Ok(_forecast.ToArray());
    }

    [HttpDelete]
    [Authorize(Scope.Delete)]
    public IActionResult Delete()
    {
        _forecast.RemoveAt(_forecast.Count - 1);

        return NoContent();
    }
}
