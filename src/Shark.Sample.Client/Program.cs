using Shark.Sample.Client.ApplicationServices;
using Shark.Sample.Client.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

builder.Services.AddTransient<ISecurityService, SecurityService>();
builder.Services.AddTransient<IWeatherForecastService, WeatherForecastService>();
builder.Services.AddTransient<ICallBackApplicationService, CallBackApplicationService>();

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
    app.UseHsts();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
