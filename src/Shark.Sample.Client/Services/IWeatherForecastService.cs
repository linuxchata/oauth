using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface IWeatherForecastService
{
    Task<List<WeatherForecast>> Get(string grantType);
}