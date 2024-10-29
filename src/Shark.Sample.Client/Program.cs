using System.Security.Authentication;
using Microsoft.Extensions.Configuration;
using Shark.AuthorizationServer.Sdk.Extensions;
using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        listenOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    });
    serverOptions.AddServerHeader = false;
});

// Add services to the container.
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});

builder.Services.Configure<ProtectedResourceConfiguration>(
    builder.Configuration.GetSection(ProtectedResourceConfiguration.Name));

builder.Services.AddRazorPages();
builder.Services.AddHttpClient();

builder.Services.AddSharkClient(builder.Configuration);

builder.Services.AddTransient<IWeatherForecastService, WeatherForecastService>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHsts();
app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

await app.RunAsync();
