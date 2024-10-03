namespace Shark.AuthorizationServer.Abstractions.Services;

public interface IProofKeyForCodeExchangeService
{
    string GetCodeChallenge(string codeVerifier, string codeChallengeMethod);
}