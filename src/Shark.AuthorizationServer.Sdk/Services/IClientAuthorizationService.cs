using Shark.AuthorizationServer.Sdk.Models;

namespace Shark.AuthorizationServer.Sdk.Services;

public interface IClientAuthorizationService
{
    string BuildLoginPageUrl(string responseType, string? state, ProofKeyForCodeExchange? pkce = null);
}