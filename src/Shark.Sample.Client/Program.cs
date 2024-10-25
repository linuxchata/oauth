using Shark.Sample.Client.Abstractions.Services;
using Shark.Sample.Client.ApplicationServices;
using Shark.Sample.Client.Models;
using Shark.Sample.Client.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});

builder.Services.Configure<AuthorizationServerConfiguration>(
    builder.Configuration.GetSection(AuthorizationServerConfiguration.Name));

builder.Services.AddRazorPages();
builder.Services.AddHttpClient();

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

builder.Services.AddTransient<IAuthorizationService, AuthorizationService>();
builder.Services.AddTransient<IStringGeneratorService, StringGeneratorService>();
builder.Services.AddTransient<IProofKeyForCodeExchangeService, ProofKeyForCodeExchangeService>();
builder.Services.AddTransient<IWeatherForecastService, WeatherForecastService>();
builder.Services.AddTransient<ICallBackApplicationService, CallBackApplicationService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<IStateStore, StateStore>();
builder.Services.AddSingleton<ISecureTokenStore, SecureTokenStore>();

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
