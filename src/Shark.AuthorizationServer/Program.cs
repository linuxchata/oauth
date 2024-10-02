using Shark.AuthorizationServer.Abstractions.Services;
using Shark.AuthorizationServer.ApplicationServices;
using Shark.AuthorizationServer.Authentication;
using Shark.AuthorizationServer.Constants;
using Shark.AuthorizationServer.Models;
using Shark.AuthorizationServer.Repositories;
using Shark.AuthorizationServer.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.Configure<AuthorizationServerConfiguration>(
    builder.Configuration.GetSection(AuthorizationServerConfiguration.Name));

var basicAuthenticationOptions = new BasicAuthenticationOptions();
builder.Configuration.GetSection(BasicAuthenticationOptions.Name).Bind(basicAuthenticationOptions);

builder.Services.AddHttpClient();
builder.Services.AddDistributedMemoryCache();

builder.Services
    .AddAuthentication(Scheme.Cookies)
    .AddCookie();

builder.Services
    .AddAuthentication(Scheme.Basic)
    .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(
        Scheme.Basic,
        options => options = basicAuthenticationOptions);

builder.Services.AddTransient<IAuthorizeApplicationService, AuthorizeApplicationService>();
builder.Services.AddTransient<ITokenApplicationService, TokenApplicationService>();

builder.Services.AddTransient<IStringGeneratorService, StringGeneratorService>();
builder.Services.AddTransient<IAccessTokenGeneratorService, AccessTokenGeneratorService>();

builder.Services.AddTransient<ILoginService, LoginService>();
builder.Services.AddTransient<IResourceOwnerCredentialsValidationService, ResourceOwnerCredentialsValidationService>();

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddTransient<IRedirectionService, RedirectionService>();

builder.Services.AddSingleton<IClientRepository, ClientRepository>();
builder.Services.AddSingleton<IPersistedGrantStore, InMemoryPersistedGrantStore>();

builder.Services.AddRazorPages();
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

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
