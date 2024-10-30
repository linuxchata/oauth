using Shark.AuthorizationServer.Common.Constants;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class RefreshTokenGeneratorService(
    IStringGeneratorService stringGeneratorService) : IRefreshTokenGeneratorService
{
    private readonly IStringGeneratorService _stringGeneratorService = stringGeneratorService;

    public string? Generate(string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes, nameof(scopes));

        if (!scopes.ToHashSet().Contains(Scope.OfflineAccess))
        {
            return null;
        }

        return _stringGeneratorService.GenerateRefreshToken();
    }
}