using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Domain.Enumerations;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public sealed class ClientRepository(IOptions<SqLiteConfiguration> sqLiteConfiguration) :
    BaseSqLiteRepository(sqLiteConfiguration), IClientRepository
{
    public async Task<Client?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var commandText = @"SELECT * FROM Client WHERE ClientId = @ClientId";
        var sqliteParameters = new SqliteParameter("@ClientId", value);

        return await Execute(commandText, [sqliteParameters], (SqliteDataReader reader) =>
        {
            var client = new Client
            {
                ClientName = reader["ClientName"].ToString()!,
                Enabled = Convert.ToInt32(reader["Enabled"]) == 1,
                ClientId = reader["ClientId"].ToString()!,
                ClientSecret = reader["ClientSecret"].ToString()!,
                ClientIdIssuedAt = Convert.ToInt64(reader["ClientIdIssuedAt"]),
                ClientSecretExpiresAt = Convert.ToInt64(reader["ClientSecretExpiresAt"]),
                ClientType = GetClientType(reader["ClientType"]),
                RedirectUris = reader["RedirectUris"].ToString()!.Split(';'),
                GrantTypes = reader["GrantTypes"].ToString()!.Split(';'),
                ResponseTypes = reader["ResponseTypes"].ToString()!.Split(';'),
                TokenEndpointAuthMethod = reader["TokenEndpointAuthMethod"].ToString()!,
                ClientUri = reader["ClientUri"].ToString(),
                LogoUri = reader["LogoUri"].ToString(),
                Scope = reader["Scope"].ToString()!.Split(';'),
                Audience = reader["Audience"].ToString()!,
                RegistrationAccessToken = reader["RegistrationAccessToken"].ToString()!,
                RegistrationClientUri = reader["RegistrationClientUri"].ToString()!,
                DeviceCodeLifetimeInSeconds = GetNullableInteger(reader["DeviceCodeLifetimeInSeconds"]),
                AccessTokenLifetimeInSeconds = GetNullableInteger(reader["AccessTokenLifetimeInSeconds"]),
                RefreshTokenLifetimeInSeconds = GetNullableInteger(reader["RefreshTokenLifetimeInSeconds"]),
            };

            return client;
        });
    }

    public async Task Add(Client client)
    {
        var commandText = @"
            INSERT INTO Client
            (
                ClientName,
                Enabled,
                ClientId,
                ClientSecret,
                ClientIdIssuedAt,
                ClientSecretExpiresAt,
                ClientType,
                RedirectUris,
                GrantTypes,
                ResponseTypes,
                TokenEndpointAuthMethod,
                ClientUri,
                LogoUri,
                Scope,
                Audience,
                RegistrationAccessToken,
                RegistrationClientUri,
                DeviceCodeLifetimeInSeconds,
                AccessTokenLifetimeInSeconds,
                RefreshTokenLifetimeInSeconds
            )
            VALUES
            (
                @ClientName,
                @Enabled,
                @ClientId,
                @ClientSecret,
                @ClientIdIssuedAt,
                @ClientSecretExpiresAt,
                @ClientType,
                @RedirectUris,
                @GrantTypes,
                @ResponseTypes,
                @TokenEndpointAuthMethod,
                @ClientUri,
                @LogoUri,
                @Scope,
                @Audience,
                @RegistrationAccessToken,
                @RegistrationClientUri,
                @DeviceCodeLifetimeInSeconds,
                @AccessTokenLifetimeInSeconds,
                @RefreshTokenLifetimeInSeconds
            )";
        var sqliteParameters = new SqliteParameter[]
        {
            new("@ClientName", client.ClientName),
            new("@Enabled", client.Enabled),
            new("@ClientId", client.ClientId),
            new("@ClientSecret", client.ClientSecret),
            new("@ClientIdIssuedAt", client.ClientIdIssuedAt),
            new("@ClientSecretExpiresAt", client.ClientSecretExpiresAt),
            new("@ClientType", client.ClientType),
            new("@RedirectUris", string.Join(';', client.RedirectUris)),
            new("@GrantTypes", string.Join(';', client.GrantTypes)),
            new("@ResponseTypes", string.Join(';', client.ResponseTypes)),
            new("@TokenEndpointAuthMethod", client.TokenEndpointAuthMethod),
            new("@ClientUri", SetNullableValue(client.ClientUri)),
            new("@LogoUri", SetNullableValue(client.LogoUri)),
            new("@Scope", string.Join(';', client.Scope)),
            new("@Audience", client.Audience),
            new("@RegistrationAccessToken", client.RegistrationAccessToken),
            new("@RegistrationClientUri", client.RegistrationClientUri),
            new("@DeviceCodeLifetimeInSeconds", SetNullableValue(client.DeviceCodeLifetimeInSeconds)),
            new("@AccessTokenLifetimeInSeconds", SetNullableValue(client.AccessTokenLifetimeInSeconds)),
            new("@RefreshTokenLifetimeInSeconds", SetNullableValue(client.RefreshTokenLifetimeInSeconds)),
        };

        await Execute(commandText, sqliteParameters);
    }

    public async Task Remove(string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            var commandText = @"DELETE FROM Client WHERE ClientId = @ClientId";
            var sqliteParameters = new SqliteParameter("@ClientId", value);

            await Execute(commandText, [sqliteParameters]);
        }
    }

    private ClientType GetClientType(object? value)
    {
        if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
        {
            return ClientType.Public;
        }

        return Enum.TryParse(value.ToString(), out ClientType clientType) ? clientType : ClientType.Public;
    }
}