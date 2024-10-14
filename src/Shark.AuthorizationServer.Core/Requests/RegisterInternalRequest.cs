﻿namespace Shark.AuthorizationServer.Core.Requests;

public sealed class RegisterInternalRequest
{
    public required string[] RedirectUris { get; set; }

    public string? TokenEndpointAuthMethod { get; set; }

    public required string GrantTypes { get; set; }

    public required string ResponseTypes { get; set; }

    public required string ClientName { get; set; }

    public string? ClientUri { get; set; }

    public string? LogoUri { get; set; }

    public required string Scope { get; set; }

    public required string Audience { get; set; }
}