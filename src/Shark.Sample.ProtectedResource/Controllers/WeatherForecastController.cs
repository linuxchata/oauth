using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shark.Sample.ProtectedResource.Constants;

namespace Shark.Sample.ProtectedResource.Controllers;

[ApiController]
[Route("[controller]")]
public sealed class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries =
    [
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    ];

    private readonly List<WeatherForecast> _forecast;

    public WeatherForecastController()
    {
        _forecast = Enumerable.Range(1, 4).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-35, 40),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        }).ToList();
    }

    [HttpGet]
    [Authorize(CustomScope.Read)]
    [Produces(MediaTypeNames.Application.Json)]
    [ProducesResponseType<WeatherForecast[]>(StatusCodes.Status200OK)]
    public IActionResult Get()
    {
        return Ok(_forecast.ToArray());
    }

    [HttpDelete]
    [Authorize(CustomScope.Delete)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public IActionResult Delete()
    {
        _forecast.RemoveAt(_forecast.Count - 1);

        return NoContent();
    }
}
