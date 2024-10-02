namespace Shark.Sample.Client.Models;

public sealed class ProofKeyForCodeExchange
{
    public required string CodeVerifier { get; set; }

    public required string CodeChallenge { get; set; }

    public required string CodeChallengeMethod { get; set; }
}