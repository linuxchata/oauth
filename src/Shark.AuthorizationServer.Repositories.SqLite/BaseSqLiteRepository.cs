using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public abstract class BaseSqLiteRepository(IOptions<SqLiteConfiguration> sqLiteConfiguration)
{
    private readonly SqLiteConfiguration _sqLiteConfiguration = sqLiteConfiguration.Value;

    protected async Task<T?> Execute<T>(
        string commandText,
        SqliteParameter[] sqliteParameters,
        Func<SqliteDataReader, T> handler)
    {
        using var connection = new SqliteConnection(_sqLiteConfiguration.ConnectionString);
        await connection.OpenAsync();

        var command = connection.CreateCommand();
        command.CommandText = commandText;
        command.Parameters.AddRange(sqliteParameters);

        using var reader = await command.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return handler(reader);
        }

        return default;
    }

    protected async Task Execute(string commandText, SqliteParameter[] sqliteParameters)
    {
        using var connection = new SqliteConnection(@"Data Source=C:\src\oauth\data\oauth.db");
        await connection.OpenAsync();

        var command = connection.CreateCommand();
        command.CommandText = commandText;
        command.Parameters.AddRange(sqliteParameters);

        await command.ExecuteNonQueryAsync();
    }

    protected int? GetNullableInteger(object? value)
    {
        if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
        {
            return null;
        }

        return Convert.ToInt32(value);
    }

    protected bool? GetNullableBoolean(object? value)
    {
        if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
        {
            return null;
        }

        return Convert.ToBoolean(value);
    }

    protected object SetNullableValue(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) ? value : DBNull.Value;
    }

    protected object SetNullableValue(int? value)
    {
        return value.HasValue ? value : DBNull.Value;
    }

    protected object SetNullableValue(bool? value)
    {
        return value.HasValue ? value : DBNull.Value;
    }
}