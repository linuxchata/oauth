namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalResponse(TokenResponse tokenResponse) : ITokenInternalResponse
{
    public TokenResponse TokenResponse { get; set; } = tokenResponse;
}