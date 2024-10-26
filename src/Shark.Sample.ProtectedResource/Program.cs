using System.Security.Authentication;
using Shark.AuthorizationServer.Client.Constants;
using Shark.AuthorizationServer.Client.Extensions;
using Shark.Sample.ProtectedResource.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(listenOptions =>
    {
        listenOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    });
});

// Add services to the container.
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});

builder.Services.AddSharkAuthentication(builder.Configuration);

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

app.UseHsts();
app.UseHttpsRedirection();

app.UseAuthorization();

app.UseNoSniffHeaders();

app.MapControllers();

await app.RunAsync();
