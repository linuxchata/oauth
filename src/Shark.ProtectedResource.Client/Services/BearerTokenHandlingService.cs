﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Shark.ProtectedResource.Client.Constants;
using Shark.ProtectedResource.Client.Models;

namespace Shark.ProtectedResource.Client.Services
{
    public sealed class BearerTokenHandlingService : IBearerTokenHandlingService
    {
        private const string HeaderKeyName = "Authorization";
        private const string BearerTokenName = "Bearer";

        private readonly RsaSecurityKey _rsaSecurityKey;
        private readonly BearerTokenAuthenticationOptions _configuration;

        public BearerTokenHandlingService(
            RsaSecurityKey rsaSecurityKey,
            IOptions<BearerTokenAuthenticationOptions> options,
            ILogger<BearerTokenHandlingService> logger)
        {
            _rsaSecurityKey = rsaSecurityKey;
            _configuration = options.Value;
        }

        public string? GetAccessToken(IHeaderDictionary headers)
        {
            if (!headers.TryGetValue(HeaderKeyName, out StringValues headerValue))
            {
                return null;
            }

            if (headerValue == StringValues.Empty)
            {
                return null;
            }

            var authorization = headerValue.ToString();

            if (!authorization.StartsWith(BearerTokenName, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var startIndexOfAccessToken = authorization.IndexOf(BearerTokenName) + 1;
            var accessToken = authorization[(startIndexOfAccessToken + BearerTokenName.Length)..];

            return accessToken;
        }

        public bool ParseAndValidateAccessToken(string accessToken, out TokenIdentity tokenIdentity)
        {
            tokenIdentity = new TokenIdentity();

            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(accessToken))
            {
                return false;
            }

            var jwtToken = handler.ReadJwtToken(accessToken);
            if (!ValidateAccessToken(handler, jwtToken, accessToken, ref tokenIdentity))
            {
                return false;
            }

            var userId = jwtToken.Subject;
            var scopes = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimType.Scope)?.Value?.Split(' ');

            tokenIdentity.UserId = userId;
            tokenIdentity.Scopes = scopes!;

            return true;
        }

        private bool ValidateAccessToken(
            JwtSecurityTokenHandler handler,
            JwtSecurityToken jwtToken,
            string accessToken,
            ref TokenIdentity tokenIdentity)
        {
            tokenIdentity = new TokenIdentity();

            var securityKey = GetIssuerSigningKey(jwtToken.SignatureAlgorithm);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidIssuer = _configuration.Issuer,
                ValidateAudience = false,
                ValidAudiences = new List<string> { _configuration.Audience },
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(10),
            };

            try
            {
                handler.ValidateToken(accessToken, validationParameters, out SecurityToken validatedToken);
                if (!(validatedToken is JwtSecurityToken))
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        private SecurityKey GetIssuerSigningKey(string signatureAlgorithm)
        {
            if (signatureAlgorithm == SecurityAlgorithms.HmacSha256)
            {
                var key = Encoding.UTF8.GetBytes(_configuration.SymmetricSecurityKey);

                return new SymmetricSecurityKey(key)
                {
                    KeyId = _configuration.KeyId
                };
            }
            else if (signatureAlgorithm == SecurityAlgorithms.RsaSha256)
            {
                return _rsaSecurityKey;
            }

            throw new InvalidOperationException($"Unsupported signature algorithms {signatureAlgorithm}");
        }
    }
}