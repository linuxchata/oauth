namespace Shark.AuthorizationServer.Core.Constants;

public static class Error
{
    public const string UnsupportedResponseType = "unsupported_response_type";

    public const string UnauthorizedClient = "unauthorized_client";

    public const string InvalidClient = "invalid_client";

    public const string InvalidGrant = "invalid_grant";

    public const string InvalidGrantType = "invalid_grant_type";

    public const string UnsupportedGrantType = "unsupported_grant_type";

    public const string InvalidScope = "invalid_scope";

    public const string InvalidRequest = "invalid_request";

    public const string InvalidRedirectUri = "invalid_redirect_uri";

    public const string InvalidClientMetadata = "invalid_client_metadata";

    public const string AuthorizationPending = "authorization_pending";
}