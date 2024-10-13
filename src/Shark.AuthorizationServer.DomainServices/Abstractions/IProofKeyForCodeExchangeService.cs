namespace Shark.AuthorizationServer.DomainServices.Abstractions;

public interface IProofKeyForCodeExchangeService
{
    string GetCodeChallenge(string codeVerifier, string codeChallengeMethod);
}