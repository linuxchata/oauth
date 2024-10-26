using Shark.AuthorizationServer.Common;
using Shark.AuthorizationServer.Common.Extensions;
using Shark.AuthorizationServer.DomainServices.Abstractions;
using Shark.AuthorizationServer.DomainServices.Constants;

namespace Shark.AuthorizationServer.DomainServices.Services;

public sealed class ProofKeyForCodeExchangeService : IProofKeyForCodeExchangeService
{
    public string GetCodeChallenge(string codeVerifier, string codeChallengeMethod)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier, nameof(codeVerifier));
        ArgumentException.ThrowIfNullOrWhiteSpace(codeChallengeMethod, nameof(codeChallengeMethod));

        if (!codeChallengeMethod.EqualsTo(CodeChallengeMethod.Sha256))
        {
            throw new ArgumentException("Unknown code challenge method");
        }

        return ProofKeyForCodeExchangeProvider.GetCodeChallenge(codeVerifier);
    }
}