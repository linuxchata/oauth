using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Shark.AuthorizationServer.Core.Abstractions.Repositories;
using Shark.AuthorizationServer.Domain;
using Shark.AuthorizationServer.Repositories.SqLite.Configurations;

namespace Shark.AuthorizationServer.Repositories.SqLite;

public sealed class RevokeTokenRepository(IOptions<SqLiteConfiguration> sqLiteConfiguration) :
    BaseSqLiteRepository(sqLiteConfiguration), IRevokeTokenRepository
{
    public async Task<RevokeToken?> Get(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var commandText = @"SELECT * FROM RevokeToken WHERE TokenId = @TokenId";
        var sqliteParameters = new SqliteParameter("@TokenId", value);

        return await Execute(commandText, [sqliteParameters], (SqliteDataReader reader) =>
        {
            return new RevokeToken(
                reader["TokenId"].ToString()!,
                Convert.ToDateTime(reader["RevokedAt"]));
        });
    }

    public async Task Add(RevokeToken item)
    {
        var commandText = @"INSERT INTO RevokeToken (TokenId, RevokedAt) VALUES (@TokenId, @RevokedAt)";
        var sqliteParameters = new SqliteParameter[]
        {
            new("@TokenId", item.TokenId),
            new("@RevokedAt", item.RevokedAt.ToString("yyyy-MM-dd HH:mm:ss")),
        };

        await Execute(commandText, sqliteParameters);
    }
}