using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public sealed class DevicePersistedGrantRepository(IOptions<SqLiteConfiguration> sqLiteConfiguration) :
    BaseSqLiteRepository(sqLiteConfiguration), IDevicePersistedGrantRepository
{
    public async Task<DevicePersistedGrant?> GetByUserCode(string? userCode)
    {
        if (string.IsNullOrWhiteSpace(userCode))
        {
            return null;
        }

        var commandText = @"SELECT * FROM DevicePersistedGrant WHERE UserCode = @UserCode";
        var sqliteParameter = new SqliteParameter("@UserCode", userCode);

        return await GetInternal(commandText, sqliteParameter);
    }

    public async Task<DevicePersistedGrant?> GetByDeviceCode(string? deviceCode)
    {
        if (string.IsNullOrWhiteSpace(deviceCode))
        {
            return null;
        }

        var commandText = @"SELECT * FROM DevicePersistedGrant WHERE DeviceCode = @DeviceCode";
        var sqliteParameter = new SqliteParameter("@DeviceCode", deviceCode);

        return await GetInternal(commandText, sqliteParameter);
    }

    public async Task Add(DevicePersistedGrant item)
    {
        var commandText = @"
            INSERT INTO DevicePersistedGrant
            (
                Type,
                ClientId,
                Scopes,
                DeviceCode,
                UserCode,
                IsAuthorized,
                CreatedDate,
                ExpiredIn
            )
            VALUES
            (
                @Type,
                @ClientId,
                @Scopes,
                @DeviceCode,
                @UserCode,
                @IsAuthorized,
                @CreatedDate,
                @ExpiredIn
            )";
        var sqliteParameters = new SqliteParameter[]
        {
            new("@Type", item.Type),
            new("@ClientId", item.ClientId),
            new("@Scopes", string.Join(';', item.Scopes)),
            new("@DeviceCode", item.DeviceCode),
            new("@UserCode", item.UserCode),
            new("@IsAuthorized", SetNullableValue(item.IsAuthorized)),
            new("@CreatedDate", item.CreatedDate.ToString("yyyy-MM-dd HH:mm:ss")),
            new("@ExpiredIn", item.ExpiredIn),
        };

        await Execute(commandText, sqliteParameters);
    }

    public async Task Update(DevicePersistedGrant item, bool isAuthorized)
    {
        if (!string.IsNullOrWhiteSpace(item.DeviceCode))
        {
            var commandText = @"UPDATE DevicePersistedGrant SET IsAuthorized = @IsAuthorized WHERE DeviceCode = @DeviceCode";
            var sqliteParameters = new SqliteParameter[]
            {
                new("@IsAuthorized", isAuthorized),
                new("@DeviceCode", item.DeviceCode),
            };

            await Execute(commandText, sqliteParameters);
        }
    }

    public async Task Remove(DevicePersistedGrant item)
    {
        if (!string.IsNullOrWhiteSpace(item.DeviceCode))
        {
            var commandText = @"DELETE FROM DevicePersistedGrant WHERE DeviceCode = @DeviceCode";
            var sqliteParameters = new SqliteParameter("@DeviceCode", item.DeviceCode);

            await Execute(commandText, [sqliteParameters]);
        }
    }

    private async Task<DevicePersistedGrant?> GetInternal(string commandText, SqliteParameter sqliteParameter)
    {
        return await Execute(commandText, [sqliteParameter], (SqliteDataReader reader) =>
        {
            var persistedGrant = new DevicePersistedGrant
            {
                Type = reader["Type"].ToString()!,
                ClientId = reader["ClientId"].ToString()!,
                Scopes = reader["Scopes"].ToString()!.Split(';'),
                DeviceCode = reader["DeviceCode"].ToString()!,
                UserCode = reader["UserCode"].ToString()!,
                IsAuthorized = GetNullableBoolean(reader["IsAuthorized"]),
                CreatedDate = Convert.ToDateTime(reader["CreatedDate"]),
                ExpiredIn = Convert.ToInt32(reader["ExpiredIn"]),
            };

            return persistedGrant;
        });
    }
}