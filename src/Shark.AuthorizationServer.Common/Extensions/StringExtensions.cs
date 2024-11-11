namespace Shark.AuthorizationServer.Common.Extensions;

public static class StringExtensions
{
    private static readonly HashSet<char> ForbiddenChars = ['<', '>', '\n', '\r', '\''];

    public static bool EqualsTo(this string? a, string? b, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
    {
        return string.Equals(a, b, comparison);
    }

    public static string Sanitize(this string? input)
    {
        return new string(input?.Where(c => !ForbiddenChars.Contains(c)).ToArray());
    }
}
