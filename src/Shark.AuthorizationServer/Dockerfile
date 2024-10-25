# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER app
WORKDIR /app
EXPOSE 7000
EXPOSE 7001

# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Shark.AuthorizationServer/Shark.AuthorizationServer.csproj", "Shark.AuthorizationServer/"]
COPY ["Shark.AuthorizationServer.Core/Shark.AuthorizationServer.Core.csproj", "Shark.AuthorizationServer.Core/"]
COPY ["Shark.AuthorizationServer.DomainServices/Shark.AuthorizationServer.DomainServices.csproj", "Shark.AuthorizationServer.DomainServices/"]
COPY ["Shark.AuthorizationServer.Common/Shark.AuthorizationServer.Common.csproj", "Shark.AuthorizationServer.Common/"]
COPY ["Shark.AuthorizationServer.Domain/Shark.AuthorizationServer.Domain.csproj", "Shark.AuthorizationServer.Domain/"]
COPY ["Shark.AuthorizationServer.Repositories/Shark.AuthorizationServer.Repositories.csproj", "Shark.AuthorizationServer.Repositories/"]
COPY ["Shark.ProtectedResource.Client/Shark.AuthorizationServer.Client.csproj", "Shark.ProtectedResource.Client/"]
RUN dotnet restore "./Shark.AuthorizationServer/Shark.AuthorizationServer.csproj"
COPY . .
WORKDIR "/src/Shark.AuthorizationServer"
RUN dotnet build "./Shark.AuthorizationServer.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Shark.AuthorizationServer.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Shark.AuthorizationServer.dll"]