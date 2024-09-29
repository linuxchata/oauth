using Newtonsoft.Json;

namespace Shark.Sample.Client.Models;

public sealed class WeatherForecast
{
    [JsonProperty(PropertyName = "date")]
    public DateOnly Date { get; set; }

    [JsonProperty(PropertyName = "temperatureC")]
    public int TemperatureC { get; set; }

    [JsonProperty(PropertyName = "temperatureF")]
    public int TemperatureF { get; set; }

    [JsonProperty(PropertyName = "summary")]
    public string? Summary { get; set; }
}
