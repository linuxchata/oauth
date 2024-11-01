using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.DomainServices.Abstractions;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class ProofKeyForCodeExchangeService : IProofKeyForCodeExchangeService
{
    public string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier, nameof(codeVerifier));
        ArgumentException.ThrowIfNullOrWhiteSpace(codeChallengeMethod, nameof(codeChallengeMethod));

        return ProofKeyForCodeExchangeProvider.GetCodeChallenge(codeVerifier, codeChallengeMethod);
    }
}