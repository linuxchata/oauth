namespace Shark.AuthorizationServer.Common.Extensions;

public static class StringExtensions
{
    public static bool EqualsTo(this string? a, string? b, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
    {
        return string.Equals(a, b, comparison);
    }
}
