using Prometheus;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.ApplicationServices;
using Shark.AuthorizationServer.DomainServices;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.Extensions;
using Shark.AuthorizationServer.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});

builder.Services.AddHttpClient();
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

builder.Services.AddCustomAuthentication(builder.Configuration);

builder.Services.AddTransient<IAuthorizeApplicationService, AuthorizeApplicationService>();
builder.Services.AddTransient<ITokenApplicationService, TokenApplicationService>();
builder.Services.AddTransient<IIntrospectApplicationService, IntrospectApplicationService>();
builder.Services.AddTransient<IRevokeApplicationService, RevokeApplicationService>();
builder.Services.AddTransient<IConfigurationApplicationService, ConfigurationApplicationService>();
builder.Services.AddTransient<IRegisterApplicationService, RegisterApplicationService>();

builder.Services.AddTransient<IStringGeneratorService, StringGeneratorService>();
builder.Services.AddTransient<IAccessTokenGeneratorService, AccessTokenGeneratorService>();
builder.Services.AddTransient<IProofKeyForCodeExchangeService, ProofKeyForCodeExchangeService>();
builder.Services.AddTransient<ILoginService, LoginService>();
builder.Services.AddTransient<IResourceOwnerCredentialsValidationService, ResourceOwnerCredentialsValidationService>();
builder.Services.AddTransient<IRedirectionService, RedirectionService>();

builder.Services.AddSingleton<IClientRepository, ClientRepository>();
builder.Services.AddSingleton<IPersistedGrantRepository, PersistedGrantRepository>();
builder.Services.AddSingleton<IRevokeTokenRepository, RevokeTokenRepository>();

builder.Services.AddRazorPages();
builder.Services.AddControllers();
builder.Services.AddRouting(options => options.LowercaseUrls = true);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseMetricServer();

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

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
