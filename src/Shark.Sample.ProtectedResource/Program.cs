using Shark.AuthorizationServer.Client.Extensions;
using Shark.Sample.ProtectedResource.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "dd-MM-yyyy HH:mm:ss ";
    options.SingleLine = true;
});

builder.Services.AddSharkAuthentication(builder.Configuration);
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

app.Run();
