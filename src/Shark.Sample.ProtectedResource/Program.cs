using Shark.Sample.ProtectedResource.Authentication;
using Shark.Sample.ProtectedResource.Models;
using Shark.Sample.ProtectedResource.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.Configure<BearerTokenAuthenticationOptions>(
    builder.Configuration.GetSection(BearerTokenAuthenticationOptions.Name));

var bearerTokenAuthenticationOptions = new BearerTokenAuthenticationOptions();
builder.Configuration.GetSection(BearerTokenAuthenticationOptions.Name).Bind(bearerTokenAuthenticationOptions);

builder.Services.AddTransient<IBearerTokenHandlingService, BearerTokenHandlingService>();

builder.Services
    .AddAuthentication(Scheme.Bearer)
    .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
        Scheme.Bearer,
        options => options = bearerTokenAuthenticationOptions);

builder.Services
    .AddAuthorizationBuilder()
    .AddPolicy(Scope.Read, policy =>
    {
        policy.AddAuthenticationSchemes(Scheme.Bearer);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(ClaimType.Scope, Scope.Read);
    })
    .AddPolicy(Scope.Delete, policy =>
    {
        policy.AddAuthenticationSchemes(Scheme.Bearer);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(ClaimType.Scope, Scope.Delete);
    });

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthorization();

app.MapControllers();

app.Run();
