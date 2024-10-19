namespace Shark.AuthorizationServer.Core.Responses.Token;

public sealed class TokenInternalResponse(TokenResponse tokenResponse) : TokenInternalBaseResponse
{
    public TokenResponse TokenResponse { get; set; } = tokenResponse;
}