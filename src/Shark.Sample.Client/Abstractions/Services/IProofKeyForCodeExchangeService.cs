using Shark.Sample.Client.Models;

namespace Shark.Sample.Client.Abstractions.Services;

public interface IProofKeyForCodeExchangeService
{
    ProofKeyForCodeExchange Generate();

    ProofKeyForCodeExchange? Get(string codeChallenge);
}
