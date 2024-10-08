﻿using Microsoft.AspNetCore.Authentication;

namespace Shark.ProtectedResource.Client.Models
{
    public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
    {
        public const string Name = nameof(BearerTokenAuthenticationOptions);

        public string Issuer { get; set; } = null!;

        public string Audience { get; set; } = null!;

        public string KeyId { get; set; } = null!;

        public string SymmetricSecurityKey { get; set; } = null!;
    }
}