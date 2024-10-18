namespace Shark.AuthorizationServer.Core.Responses.Revoke;

public sealed class RevokeInternalBadRequestResponse : RevokeInternalBaseResponse
{
    public string Message { get; init; } = "unsupported_token_type";
}
