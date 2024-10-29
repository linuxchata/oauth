using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Abstractions.Services;

public interface IProofKeyForCodeExchangeService
{
    ProofKeyForCodeExchange? Get(string? state);

    ProofKeyForCodeExchange Generate(string? state);
}
