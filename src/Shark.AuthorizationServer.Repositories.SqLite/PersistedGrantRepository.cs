using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public sealed class PersistedGrantRepository(IOptions<SqLiteConfiguration> sqLiteConfiguration) :
    BaseSqLiteRepository(sqLiteConfiguration), IPersistedGrantRepository
{
    public async Task<PersistedGrant?> GetByValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var commandText = @"SELECT * FROM PersistedGrant WHERE Value = @Value";
        var sqliteParameter = new SqliteParameter("@Value", value);

        return await GetInternal(commandText, sqliteParameter);
    }

    public async Task<PersistedGrant?> GetByAccessTokenId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var commandText = @"SELECT * FROM PersistedGrant WHERE AccessTokenId = @AccessTokenId";
        var sqliteParameter = new SqliteParameter("@AccessTokenId", value);

        return await GetInternal(commandText, sqliteParameter);
    }

    public async Task Add(PersistedGrant item)
    {
        var commandText = @"
            INSERT INTO PersistedGrant
            (
                Type,
                ClientId,
                RedirectUri,
                Scopes,
                AccessTokenId,
                Value,
                Claims,
                CodeChallenge,
                CodeChallengeMethod,
                CreatedDate,
                ExpiredIn
            )
            VALUES
            (
                @Type,
                @ClientId,
                @RedirectUri,
                @Scopes,
                @AccessTokenId,
                @Value,
                @Claims,
                @CodeChallenge,
                @CodeChallengeMethod,
                @CreatedDate,
                @ExpiredIn
            )";
        var sqliteParameters = new SqliteParameter[]
        {
            new("@Type", item.Type),
            new("@ClientId", item.ClientId),
            new("@RedirectUri", item.RedirectUri),
            new("@Scopes", string.Join(';', item.Scopes)),
            new("@AccessTokenId", SetNullableValue(item.AccessTokenId)),
            new("@Value", item.Value),
            new("@Claims", SetNullableValue(JsonSerializer.Serialize(item.Claims))),
            new("@CodeChallenge", SetNullableValue(item.CodeChallenge)),
            new("@CodeChallengeMethod", SetNullableValue(item.CodeChallengeMethod)),
            new("@CreatedDate", item.CreatedDate.ToString("yyyy-MM-dd HH:mm:ss")),
            new("@ExpiredIn", item.ExpiredIn),
        };

        await Execute(commandText, sqliteParameters);
    }

    public async Task Remove(PersistedGrant item)
    {
        if (item != null)
        {
            if (!string.IsNullOrWhiteSpace(item.Value))
            {
                var commandText = @"DELETE FROM PersistedGrant WHERE Value = @Value";
                var sqliteParameters = new SqliteParameter("@Value", item.Value);

                await Execute(commandText, [sqliteParameters]);
            }
        }
    }

    private async Task<PersistedGrant?> GetInternal(string commandText, SqliteParameter sqliteParameter)
    {
        return await Execute(commandText, [sqliteParameter], (SqliteDataReader reader) =>
        {
            var persistedGrant = new PersistedGrant
            {
                Type = reader["Type"].ToString()!,
                ClientId = reader["ClientId"].ToString()!,
                RedirectUri = reader["RedirectUri"].ToString(),
                Scopes = reader["Scopes"].ToString()!.Split(';'),
                AccessTokenId = reader["AccessTokenId"].ToString(),
                Value = reader["Value"].ToString()!,
                Claims = JsonSerializer.Deserialize<CustomClaim[]>(reader["Claims"].ToString()!) ?? [],
                CodeChallenge = reader["CodeChallenge"].ToString(),
                CodeChallengeMethod = reader["CodeChallengeMethod"].ToString(),
                CreatedDate = Convert.ToDateTime(reader["CreatedDate"]),
                ExpiredIn = Convert.ToInt32(reader["ExpiredIn"]),
            };

            return persistedGrant;
        });
    }
}