namespace Shark.AuthorizationServer.Responses;

public sealed class RevokeInternalBadRequestResponse : RevokeInternalBaseResponse
{
    public string Message { get; init; } = "unsupported_token_type";
}
