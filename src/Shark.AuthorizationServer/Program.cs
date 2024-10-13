using Prometheus;
using Shark.AuthorizationServer.Authentication;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Core.Abstractions.ApplicationServices;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Core.ApplicationServices;
using Shark.AuthorizationServer.Core.Configurations;
using Shark.AuthorizationServer.DomainServices;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Configurations;
using Shark.AuthorizationServer.Repositories;

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

var authorizationServerConfiguration = new AuthorizationServerConfiguration();
builder.Configuration.GetSection(AuthorizationServerConfiguration.Name).Bind(authorizationServerConfiguration);
var rsaSecurityKey = Rsa256KeysGenerator.GetRsaSecurityKey();
builder.Services.AddSingleton(rsaSecurityKey);

var basicAuthenticationOptions = new BasicAuthenticationOptions();
builder.Configuration.GetSection(BasicAuthenticationOptions.Name).Bind(basicAuthenticationOptions);

builder.Services.AddHttpClient();
builder.Services.AddDistributedMemoryCache();

// Authentication session
builder.Services
    .AddAuthentication(Scheme.Cookies)
    .AddCookie();

// Basic authentication
builder.Services
    .AddAuthentication(Scheme.Basic)
    .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(
        Scheme.Basic,
        options => options = basicAuthenticationOptions);

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

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
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
