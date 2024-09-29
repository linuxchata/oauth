using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Services;

public interface IWeatherForecastService
{
    Task<List<WeatherForecast>> Get();

    Task<List<WeatherForecast>> GetWithClientCredentials();

    Task<List<WeatherForecast>> GetWithResourceOwnerCredentials();
}